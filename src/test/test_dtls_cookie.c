/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_dtls_cookie.c - DTLS Cookie Exchange Tests
 *
 * Part of the Socket Library Test Suite (Section 8.1)
 *
 * Tests:
 * 1. Cookie exchange enable/disable
 * 2. Cookie secret setting
 * 3. Cookie secret rotation
 * 4. Cookie exchange on server context
 * 5. Cookie rejection on client context
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

/* Helper to generate temporary self-signed certificate */
static int
generate_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[1024];

  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=localhost' -batch 2>/dev/null",
            key_file, cert_file);
  if (system (cmd) != 0)
    return -1;

  return 0;
}

static void
remove_test_certs (const char *cert_file, const char *key_file)
{
  unlink (cert_file);
  unlink (key_file);
}

/* ==================== Cookie Exchange Enable Tests ==================== */

TEST (dtls_cookie_enable_on_server)
{
  const char *cert_file = "test_dtls_cookie_srv.crt";
  const char *key_file = "test_dtls_cookie_srv.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Initially cookie exchange should be disabled */
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 0);

    /* Enable cookie exchange */
    SocketDTLSContext_enable_cookie_exchange (ctx);
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 1);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (dtls_cookie_enable_on_client_fails)
{
  SocketDTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Cookie exchange on client should fail */
    TRY { SocketDTLSContext_enable_cookie_exchange (ctx); }
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

/* ==================== Cookie Secret Tests ==================== */

TEST (dtls_cookie_set_secret)
{
  const char *cert_file = "test_dtls_cookie_secret.crt";
  const char *key_file = "test_dtls_cookie_secret.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set explicit cookie secret (32 bytes required) */
    unsigned char secret[32];
    memset (secret, 0x42, 32);
    SocketDTLSContext_set_cookie_secret (ctx, secret, 32);

    /* Should enable cookie exchange */
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 1);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (dtls_cookie_secret_wrong_length_fails)
{
  const char *cert_file = "test_dtls_cookie_len.crt";
  const char *key_file = "test_dtls_cookie_len.key";
  SocketDTLSContext_T ctx = NULL;
  volatile int caught = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Wrong secret length (not 32 bytes) should fail */
    unsigned char short_secret[16];
    memset (short_secret, 0x42, 16);

    TRY { SocketDTLSContext_set_cookie_secret (ctx, short_secret, 16); }
    EXCEPT (SocketDTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

/* ==================== Cookie Rotation Tests ==================== */

TEST (dtls_cookie_rotate_secret)
{
  const char *cert_file = "test_dtls_cookie_rot.crt";
  const char *key_file = "test_dtls_cookie_rot.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable cookie exchange */
    SocketDTLSContext_enable_cookie_exchange (ctx);
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 1);

    /* Rotate secret */
    SocketDTLSContext_rotate_cookie_secret (ctx);

    /* Should still have cookie exchange enabled */
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 1);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (dtls_cookie_multiple_rotations)
{
  const char *cert_file = "test_dtls_cookie_multi.crt";
  const char *key_file = "test_dtls_cookie_multi.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    SocketDTLSContext_enable_cookie_exchange (ctx);

    /* Multiple rotations should be safe */
    for (int i = 0; i < 10; i++)
      {
        SocketDTLSContext_rotate_cookie_secret (ctx);
        ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 1);
      }
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

/* ==================== Cookie Query Tests ==================== */

TEST (dtls_cookie_has_exchange_initially_false)
{
  const char *cert_file = "test_dtls_cookie_query.crt";
  const char *key_file = "test_dtls_cookie_query.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Initially false */
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 0);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (dtls_cookie_has_exchange_client_false)
{
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Client should always return false */
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 0);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Cookie Secret Null Tests ==================== */

TEST (dtls_cookie_secret_null_fails)
{
  const char *cert_file = "test_dtls_cookie_null.crt";
  const char *key_file = "test_dtls_cookie_null.key";
  SocketDTLSContext_T ctx = NULL;
  volatile int caught = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* NULL secret should fail */
    TRY { SocketDTLSContext_set_cookie_secret (ctx, NULL, 32); }
    EXCEPT (SocketDTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

/* ==================== Server Listening with Cookie Tests ==================== */

TEST (dtls_listen_with_cookie)
{
  const char *cert_file = "test_dtls_listen.crt";
  const char *key_file = "test_dtls_listen.key";
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable cookie exchange */
    SocketDTLSContext_enable_cookie_exchange (ctx);

    /* Enable DTLS */
    SocketDTLS_enable (socket, ctx);
    /* Context is reference-counted - we still hold our reference */

    /* Listen - returns immediately without client */
    TRY
    {
      DTLSHandshakeState state = SocketDTLS_listen (socket);
      /* Should return valid state */
      ASSERT (state == DTLS_HANDSHAKE_IN_PROGRESS
              || state == DTLS_HANDSHAKE_WANT_READ
              || state == DTLS_HANDSHAKE_COOKIE_EXCHANGE
              || state == DTLS_HANDSHAKE_ERROR);
    }
    EXCEPT (SocketDTLS_Failed) { /* Expected without client */ }
    EXCEPT (SocketDTLS_HandshakeFailed) { /* Expected */ }
    END_TRY;
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
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

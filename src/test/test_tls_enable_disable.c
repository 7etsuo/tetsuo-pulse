/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_enable_disable.c - TLS Enable/Disable Lifecycle Tests
 *
 * Part of the Socket Library Test Suite (Section 8.1)
 *
 * Tests:
 * 1. TLS enable on valid socket
 * 2. TLS disable lifecycle
 * 3. Double enable detection
 * 4. Enable on closed socket error handling
 * 5. State transitions
 * 6. Resource cleanup verification
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
#include "socket/Socket.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

/* Suppress -Wclobbered for volatile variables across setjmp/longjmp */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* ==================== Basic Enable Tests ==================== */

TEST (tls_enable_on_tcp_socket)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable TLS on socket */
    SocketTLS_enable (socket, ctx);

    /* Verify TLS is enabled - should not crash on info queries */
    const char *version = SocketTLS_get_version (socket);
    (void)version; /* May be NULL before handshake */
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (tls_enable_with_server_context)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;
  const char *cert_file = "test_enable_server.crt";
  const char *key_file = "test_enable_server.key";

  /* Generate test certificate */
  char cmd[1024];
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=localhost' -batch 2>/dev/null",
            key_file, cert_file);
  if (system (cmd) != 0)
    return; /* Skip if openssl not available */

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable TLS with server context */
    SocketTLS_enable (socket, ctx);
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
    unlink (cert_file);
    unlink (key_file);
  }
  END_TRY;
}

/* ==================== Double Enable Detection ==================== */

TEST (tls_double_enable_fails)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* First enable succeeds */
    SocketTLS_enable (socket, ctx);

    /* Second enable should fail */
    TRY { SocketTLS_enable (socket, ctx); }
    EXCEPT (SocketTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Disable Tests ==================== */

TEST (tls_disable_after_enable)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLS_enable (socket, ctx);

    /* Disable TLS - should not crash */
    int result = SocketTLS_disable (socket);
    /* Result may vary - just verify no crash */
    (void)result;
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (tls_disable_without_enable)
{
  Socket_T socket = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    /* Disable without enable - should be safe (no-op) */
    int result = SocketTLS_disable (socket);
    ASSERT_EQ (result, 0); /* Should indicate no TLS was enabled */
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
  }
  END_TRY;
}

/* ==================== Null Safety Tests ==================== */

TEST (tls_enable_null_socket_fails)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    TRY { SocketTLS_enable (NULL, ctx); }
    EXCEPT (SocketTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (tls_enable_null_context_fails)
{
  Socket_T socket = NULL;
  volatile int caught = 0;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    TRY { SocketTLS_enable (socket, NULL); }
    EXCEPT (SocketTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
  }
  END_TRY;
}

/* ==================== Hostname Setting Tests ==================== */

TEST (tls_set_hostname_after_enable)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLS_enable (socket, ctx);

    /* Set hostname for SNI */
    SocketTLS_set_hostname (socket, "example.com");

    /* Verify no crash - actual SNI is tested during handshake */
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (tls_set_hostname_null_rejected)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLS_enable (socket, ctx);

    /* Set valid hostname first */
    SocketTLS_set_hostname (socket, "example.com");

    /* NULL hostname should raise exception */
    TRY { SocketTLS_set_hostname (socket, NULL); }
    EXCEPT (SocketTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Info Query Before Handshake ==================== */

TEST (tls_info_queries_before_handshake)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLS_enable (socket, ctx);

    /* Info queries before handshake - should return NULL/0 safely */
    const char *cipher = SocketTLS_get_cipher (socket);
    ASSERT_NULL (cipher); /* No cipher negotiated yet */

    const char *alpn = SocketTLS_get_alpn_selected (socket);
    ASSERT_NULL (alpn); /* No ALPN negotiated yet */

    int reused = SocketTLS_is_session_reused (socket);
    ASSERT_EQ (reused, -1); /* Returns -1 before handshake complete */

    long verify_result = SocketTLS_get_verify_result (socket);
    (void)verify_result; /* Value may vary */
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Socket Free with TLS Enabled ==================== */

TEST (tls_socket_free_with_tls_enabled)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;
  int initial_count = Socket_debug_live_count ();

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLS_enable (socket, ctx);

    /* Free socket with TLS enabled - should cleanup properly */
    Socket_free (&socket);
    ASSERT_NULL (socket);

    /* Verify no socket leak */
    ASSERT_EQ (Socket_debug_live_count (), initial_count);
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Socket Pair with TLS ==================== */

TEST (tls_on_socket_pair)
{
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;
  const char *cert_file = "test_pair.crt";
  const char *key_file = "test_pair.key";

  /* Generate test certificate */
  char cmd[1024];
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=localhost' -batch 2>/dev/null",
            key_file, cert_file);
  if (system (cmd) != 0)
    return;

  TRY
  {
    /* Create socket pair */
    SocketPair_new (SOCK_STREAM, &client, &server);
    ASSERT_NOT_NULL (client);
    ASSERT_NOT_NULL (server);

    /* Create contexts */
    client_ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (client_ctx);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (server_ctx);

    /* Enable TLS on both */
    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    unlink (cert_file);
    unlink (key_file);
  }
  END_TRY;
}

/* ==================== Non-blocking Mode ==================== */

TEST (tls_enable_on_nonblocking_socket)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    /* Set non-blocking before enable */
    Socket_setnonblocking (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable TLS on non-blocking socket */
    SocketTLS_enable (socket, ctx);
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
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

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_dtls_basic.c - DTLS Basic Operations Tests
 *
 * Part of the Socket Library Test Suite (Section 8.1)
 *
 * Tests:
 * 1. DTLS enable on datagram socket
 * 2. DTLS handshake basics
 * 3. DTLS I/O operations
 * 4. DTLS shutdown
 * 5. Connection info queries
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

/* ==================== DTLS Enable Tests ==================== */

TEST (dtls_enable_on_dgram_socket)
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
    ASSERT_EQ (SocketDTLS_is_enabled (socket), 1);
    ASSERT_EQ (SocketDTLS_is_handshake_done (socket), 0);
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

TEST (dtls_enable_null_socket_fails)
{
  SocketDTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    TRY { SocketDTLS_enable (NULL, ctx); }
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

TEST (dtls_enable_null_context_fails)
{
  SocketDgram_T socket = NULL;
  volatile int caught = 0;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ASSERT_NOT_NULL (socket);

    TRY { SocketDTLS_enable (socket, NULL); }
    EXCEPT (SocketDTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
  }
  END_TRY;
}

/* ==================== DTLS State Query Tests ==================== */

TEST (dtls_state_queries_before_handshake)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);

    /* Before enable */
    ASSERT_EQ (SocketDTLS_is_enabled (socket), 0);
    ASSERT_EQ (SocketDTLS_is_handshake_done (socket), 0);
    ASSERT_EQ (SocketDTLS_is_shutdown (socket), 0);
    ASSERT_EQ (SocketDTLS_get_last_state (socket), DTLS_HANDSHAKE_NOT_STARTED);

    /* After enable */
    SocketDTLS_enable (socket, ctx);
    ASSERT_EQ (SocketDTLS_is_enabled (socket), 1);
    ASSERT_EQ (SocketDTLS_is_handshake_done (socket), 0);
    ASSERT_EQ (SocketDTLS_is_shutdown (socket), 0);
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

/* ==================== DTLS Connection Info Tests ==================== */

TEST (dtls_info_queries_before_handshake)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Info before handshake */
    const char *cipher = SocketDTLS_get_cipher (socket);
    ASSERT_NULL (cipher);

    const char *alpn = SocketDTLS_get_alpn_selected (socket);
    ASSERT_NULL (alpn);

    int reused = SocketDTLS_is_session_reused (socket);
    ASSERT_EQ (reused, 0);

    /* Version may return protocol version string */
    const char *version = SocketDTLS_get_version (socket);
    ASSERT_NOT_NULL (version);
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

/* ==================== DTLS Hostname Setting Tests ==================== */

TEST (dtls_set_hostname)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Set hostname for SNI */
    SocketDTLS_set_hostname (socket, "example.com");
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

TEST (dtls_set_peer)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Set peer address */
    SocketDTLS_set_peer (socket, "127.0.0.1", 4433);
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

/* ==================== DTLS Handshake Tests ==================== */

TEST (dtls_handshake_single_step)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Single handshake step on unconnected socket */
    TRY
    {
      DTLSHandshakeState state = SocketDTLS_handshake (socket);
      /* On unconnected socket, should get error or want state */
      ASSERT (state == DTLS_HANDSHAKE_ERROR
              || state == DTLS_HANDSHAKE_WANT_READ
              || state == DTLS_HANDSHAKE_WANT_WRITE
              || state == DTLS_HANDSHAKE_IN_PROGRESS);
    }
    EXCEPT (SocketDTLS_HandshakeFailed) { /* Expected */ }
    EXCEPT (SocketDTLS_Failed) { /* Expected */ }
    END_TRY;
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

TEST (dtls_handshake_loop_zero_timeout)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Zero timeout = non-blocking */
    TRY
    {
      DTLSHandshakeState state = SocketDTLS_handshake_loop (socket, 0);
      /* Should return immediately without blocking */
      ASSERT (state != DTLS_HANDSHAKE_COMPLETE);
    }
    EXCEPT (SocketDTLS_HandshakeFailed) { /* Expected */ }
    EXCEPT (SocketDTLS_Failed) { /* Expected */ }
    END_TRY;
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

/* ==================== DTLS I/O Before Handshake Tests ==================== */

TEST (dtls_send_before_handshake_fails)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    char buf[] = "test";
    TRY { SocketDTLS_send (socket, buf, sizeof (buf)); }
    EXCEPT (SocketDTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
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

TEST (dtls_recv_before_handshake_fails)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    char buf[64];
    TRY { SocketDTLS_recv (socket, buf, sizeof (buf)); }
    EXCEPT (SocketDTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
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

/* ==================== DTLS Shutdown Tests ==================== */

TEST (dtls_shutdown_before_handshake)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Shutdown before handshake */
    TRY { SocketDTLS_shutdown (socket); }
    EXCEPT (SocketDTLS_ShutdownFailed) { /* Expected */ }
    END_TRY;
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

/* ==================== Socket Free with DTLS Enabled ==================== */

TEST (dtls_socket_free_with_dtls_enabled)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Free should cleanup properly */
    SocketDgram_free (&socket);
    ASSERT_NULL (socket);
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

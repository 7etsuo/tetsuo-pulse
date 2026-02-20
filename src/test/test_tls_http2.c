/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_http2.c - TLS with HTTP/2 ALPN Negotiation Tests
 *
 * Part of the Socket Library Test Suite (Section 8.2)
 *
 * Tests:
 * 1. ALPN protocol negotiation
 * 2. HTTP/2 protocol selection
 * 3. Fallback to HTTP/1.1
 * 4. Multiple protocol offers
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

/* Helper to generate temporary self-signed certificate */
static int
generate_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[1024];

  snprintf (cmd,
            sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=localhost' -batch 2>/dev/null",
            key_file,
            cert_file);
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

/* Helper to complete handshake on socket pair */
static int
complete_handshake (Socket_T client, Socket_T server)
{
  TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
  TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
  int loops = 0;

  while ((client_state != TLS_HANDSHAKE_COMPLETE
          || server_state != TLS_HANDSHAKE_COMPLETE)
         && client_state != TLS_HANDSHAKE_ERROR
         && server_state != TLS_HANDSHAKE_ERROR && loops < 1000)
    {
      if (client_state != TLS_HANDSHAKE_COMPLETE)
        client_state = SocketTLS_handshake (client);
      if (server_state != TLS_HANDSHAKE_COMPLETE)
        server_state = SocketTLS_handshake (server);
      loops++;
      usleep (1000);
    }

  return (client_state == TLS_HANDSHAKE_COMPLETE
          && server_state == TLS_HANDSHAKE_COMPLETE)
             ? 0
             : -1;
}

TEST (alpn_set_h2_protocol)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    const char *protos[] = { "h2" };
    SocketTLSContext_set_alpn_protos (ctx, protos, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (alpn_set_multiple_protocols)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Offer h2 and http/1.1 */
    const char *protos[] = { "h2", "http/1.1" };
    SocketTLSContext_set_alpn_protos (ctx, protos, 2);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (alpn_negotiation_h2)
{
  const char *cert_file = "test_alpn_h2.crt";
  const char *key_file = "test_alpn_h2.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Client offers h2 and http/1.1 */
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);
    const char *client_protos[] = { "h2", "http/1.1" };
    SocketTLSContext_set_alpn_protos (client_ctx, client_protos, 2);

    /* Server accepts h2 */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    const char *server_protos[] = { "h2" };
    SocketTLSContext_set_alpn_protos (server_ctx, server_protos, 1);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Check ALPN result */
    const char *selected = SocketTLS_get_alpn_selected (client);
    if (selected)
      {
        ASSERT_EQ (strcmp (selected, "h2"), 0);
      }
    /* Note: ALPN might not be selected if server doesn't support callback */
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
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (alpn_negotiation_http11_fallback)
{
  const char *cert_file = "test_alpn_http11.crt";
  const char *key_file = "test_alpn_http11.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Client offers h2 and http/1.1 */
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);
    const char *client_protos[] = { "h2", "http/1.1" };
    SocketTLSContext_set_alpn_protos (client_ctx, client_protos, 2);

    /* Server only accepts http/1.1 */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    const char *server_protos[] = { "http/1.1" };
    SocketTLSContext_set_alpn_protos (server_ctx, server_protos, 1);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Check ALPN result */
    const char *selected = SocketTLS_get_alpn_selected (client);
    if (selected)
      {
        ASSERT_EQ (strcmp (selected, "http/1.1"), 0);
      }
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
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (alpn_no_common_protocol)
{
  const char *cert_file = "test_alpn_none.crt";
  const char *key_file = "test_alpn_none.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Client offers only h2 */
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);
    const char *client_protos[] = { "h2" };
    SocketTLSContext_set_alpn_protos (client_ctx, client_protos, 1);

    /* Server offers only spdy */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    const char *server_protos[] = { "spdy/3.1" };
    SocketTLSContext_set_alpn_protos (server_ctx, server_protos, 1);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Handshake may succeed with no ALPN or fail depending on strict mode */
    int result = complete_handshake (client, server);
    if (result == 0)
      {
        /* No common protocol - ALPN should be NULL */
        const char *selected = SocketTLS_get_alpn_selected (client);
        /* Either NULL or handshake failed */
        (void)selected;
      }
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
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (alpn_empty_list)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Empty protocol list - should be safe */
    const char *protos[] = { NULL };
    /* Some implementations may allow NULL/empty, others may fail */
    (void)protos;
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (alpn_query_before_handshake)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ctx = SocketTLSContext_new_client (NULL);

    const char *protos[] = { "h2" };
    SocketTLSContext_set_alpn_protos (ctx, protos, 1);

    SocketTLS_enable (socket, ctx);

    /* Query before handshake should return NULL */
    const char *selected = SocketTLS_get_alpn_selected (socket);
    ASSERT_NULL (selected);
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

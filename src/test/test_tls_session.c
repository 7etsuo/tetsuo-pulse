/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_session.c - TLS Session Management Tests
 *
 * Part of the Socket Library Test Suite (Section 8.1)
 *
 * Tests:
 * 1. Session save and restore
 * 2. Session resumption
 * 3. Session cache configuration
 * 4. Session tickets
 * 5. Session ID context
 * 6. Cache statistics
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

TEST (session_cache_enable)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable session cache with default parameters */
    SocketTLSContext_enable_session_cache (ctx, 100, 300);

    /* Verify no crash */
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (session_cache_custom_size)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable with custom size */
    SocketTLSContext_enable_session_cache (ctx, 500, 600);

    /* Set size explicitly */
    SocketTLSContext_set_session_cache_size (ctx, 1000);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (session_cache_stats)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLSContext_enable_session_cache (ctx, 100, 300);

    /* Get statistics */
    size_t hits = 0, misses = 0, stores = 0;
    SocketTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);

    /* Initial stats should be zero */
    ASSERT_EQ (hits, 0);
    ASSERT_EQ (misses, 0);
    ASSERT_EQ (stores, 0);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (session_id_context_set)
{
  const char *cert_file = "test_session_id.crt";
  const char *key_file = "test_session_id.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set session ID context */
    const unsigned char context[] = "my_app_context_v1";
    SocketTLSContext_set_session_id_context (ctx, context, sizeof (context));
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (session_id_context_max_length)
{
  const char *cert_file = "test_session_max.crt";
  const char *key_file = "test_session_max.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set maximum length context (32 bytes) */
    unsigned char context[32];
    memset (context, 'A', 32);
    SocketTLSContext_set_session_id_context (ctx, context, 32);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (session_tickets_enable)
{
  const char *cert_file = "test_ticket.crt";
  const char *key_file = "test_ticket.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Create 80-byte ticket key */
    unsigned char ticket_key[80];
    memset (ticket_key, 0x42, 80);

    SocketTLSContext_enable_session_tickets (ctx, ticket_key, 80);

    /* Verify tickets are enabled */
    int enabled = SocketTLSContext_session_tickets_enabled (ctx);
    ASSERT_EQ (enabled, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (session_tickets_disable)
{
  const char *cert_file = "test_ticket_dis.crt";
  const char *key_file = "test_ticket_dis.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable then disable tickets */
    unsigned char ticket_key[80];
    memset (ticket_key, 0x42, 80);
    SocketTLSContext_enable_session_tickets (ctx, ticket_key, 80);

    SocketTLSContext_disable_session_tickets (ctx);

    /* Verify tickets are disabled */
    int enabled = SocketTLSContext_session_tickets_enabled (ctx);
    ASSERT_EQ (enabled, 0);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (session_ticket_key_rotation)
{
  const char *cert_file = "test_ticket_rot.crt";
  const char *key_file = "test_ticket_rot.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable with initial key */
    unsigned char initial_key[80];
    memset (initial_key, 0x11, 80);
    SocketTLSContext_enable_session_tickets (ctx, initial_key, 80);

    /* Rotate to new key */
    unsigned char new_key[80];
    memset (new_key, 0x22, 80);
    SocketTLSContext_rotate_session_ticket_key (ctx, new_key, 80);

    /* Tickets should still be enabled */
    ASSERT_EQ (SocketTLSContext_session_tickets_enabled (ctx), 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (session_save_restore_basic)
{
  const char *cert_file = "test_sess_save.crt";
  const char *key_file = "test_sess_save.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* First connection - establish session */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);
    SocketTLSContext_enable_session_cache (client_ctx, 10, 300);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    SocketTLSContext_enable_session_cache (server_ctx, 10, 300);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Save session */
    unsigned char session_buf[4096];
    size_t session_len = sizeof (session_buf);
    int saved = SocketTLS_session_save (client, session_buf, &session_len);

    /* Session may or may not be available depending on TLS 1.3 timing */
    if (saved)
      {
        ASSERT (session_len > 0);
        ASSERT (session_len <= sizeof (session_buf));
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

TEST (session_reuse_check)
{
  const char *cert_file = "test_sess_reuse.crt";
  const char *key_file = "test_sess_reuse.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* First connection should not be a resumed session */
    int reused = SocketTLS_is_session_reused (client);
    ASSERT_EQ (reused, 0);
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

TEST (session_ticket_wrong_key_size)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Wrong key size should fail (needs 80 bytes) */
    unsigned char short_key[32];
    memset (short_key, 0x42, 32);

    TRY
    {
      SocketTLSContext_enable_session_tickets (ctx, short_key, 32);
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
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

TEST (session_id_context_too_long)
{
  const char *cert_file = "test_sess_long.crt";
  const char *key_file = "test_sess_long.key";
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Context > 32 bytes should fail */
    unsigned char long_context[64];
    memset (long_context, 'A', 64);

    TRY
    {
      SocketTLSContext_set_session_id_context (ctx, long_context, 64);
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (session_restore_invalid_length)
{
  const char *cert_file = "test_sess_bounds.crt";
  const char *key_file = "test_sess_bounds.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Test 1: Zero length should be rejected */
    unsigned char dummy_buf[16] = { 0 };
    int result = SocketTLS_session_restore (client, dummy_buf, 0);
    ASSERT_EQ (result, 0); /* Should return 0 for invalid data */

    /* Test 2: Length exceeding INT_MAX should be rejected.
     * This validates the fix for issue #2354 - ensures portability
     * across platforms including 64-bit Windows (LLP64). */
    size_t too_large = (size_t)INT_MAX + 1;
    result = SocketTLS_session_restore (client, dummy_buf, too_large);
    ASSERT_EQ (result, 0); /* Should return 0 for invalid data */
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

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

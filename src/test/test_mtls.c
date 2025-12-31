/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_mtls.c - Mutual TLS Authentication Tests
 *
 * Part of the Socket Library Test Suite (Section 8.2)
 *
 * Tests:
 * 1. Client certificate verification
 * 2. VERIFY_PEER mode
 * 3. VERIFY_FAIL_IF_NO_PEER_CERT mode
 * 4. Custom verify callback
 * 5. Client cert info retrieval
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

/* Helper to generate CA, server, and client certificates */
static int
generate_mtls_certs (const char *ca_cert,
                     const char *ca_key,
                     const char *server_cert,
                     const char *server_key,
                     const char *client_cert,
                     const char *client_key)
{
  char cmd[2048];

  /* Generate CA */
  snprintf (cmd,
            sizeof (cmd),
            "openssl genrsa -out %s 2048 2>/dev/null && "
            "openssl req -x509 -new -key %s -out %s -days 1 "
            "-subj '/CN=TestCA' -batch 2>/dev/null",
            ca_key,
            ca_key,
            ca_cert);
  if (system (cmd) != 0)
    return -1;

  /* Generate server cert signed by CA */
  snprintf (cmd,
            sizeof (cmd),
            "openssl genrsa -out %s 2048 2>/dev/null && "
            "openssl req -new -key %s -subj '/CN=localhost' -batch 2>/dev/null "
            "| openssl x509 -req -CA %s -CAkey %s -CAcreateserial -out %s "
            "-days 1 2>/dev/null",
            server_key,
            server_key,
            ca_cert,
            ca_key,
            server_cert);
  if (system (cmd) != 0)
    return -1;

  /* Generate client cert signed by CA */
  snprintf (cmd,
            sizeof (cmd),
            "openssl genrsa -out %s 2048 2>/dev/null && "
            "openssl req -new -key %s -subj '/CN=client' -batch 2>/dev/null | "
            "openssl x509 -req -CA %s -CAkey %s -CAcreateserial -out %s "
            "-days 1 2>/dev/null",
            client_key,
            client_key,
            ca_cert,
            ca_key,
            client_cert);
  if (system (cmd) != 0)
    return -1;

  return 0;
}

static void
remove_mtls_certs (const char *ca_cert,
                   const char *ca_key,
                   const char *server_cert,
                   const char *server_key,
                   const char *client_cert,
                   const char *client_key)
{
  unlink (ca_cert);
  unlink (ca_key);
  unlink (server_cert);
  unlink (server_key);
  unlink (client_cert);
  unlink (client_key);
  unlink ("TestCA.srl"); /* OpenSSL serial file */
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

/* ==================== Verify Mode Tests ==================== */

TEST (mtls_verify_peer_mode)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (mtls_verify_fail_if_no_peer_mode)
{
  const char *ca_cert = "test_mtls_ca.crt";
  const char *ca_key = "test_mtls_ca.key";
  const char *server_cert = "test_mtls_server.crt";
  const char *server_key = "test_mtls_server.key";
  const char *client_cert = "test_mtls_client.crt";
  const char *client_key = "test_mtls_client.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_mtls_certs (
          ca_cert, ca_key, server_cert, server_key, client_cert, client_key)
      != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (server_cert, server_key, ca_cert);
    ASSERT_NOT_NULL (ctx);

    /* Set mTLS mode - require client certificate */
    SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_FAIL_IF_NO_PEER_CERT);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_mtls_certs (
        ca_cert, ca_key, server_cert, server_key, client_cert, client_key);
  }
  END_TRY;
}

/* ==================== Full mTLS Handshake Tests ==================== */

TEST (mtls_successful_handshake)
{
  const char *ca_cert = "test_mtls_hs_ca.crt";
  const char *ca_key = "test_mtls_hs_ca.key";
  const char *server_cert = "test_mtls_hs_server.crt";
  const char *server_key = "test_mtls_hs_server.key";
  const char *client_cert = "test_mtls_hs_client.crt";
  const char *client_key = "test_mtls_hs_client.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_mtls_certs (
          ca_cert, ca_key, server_cert, server_key, client_cert, client_key)
      != 0)
    return;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Server requires client cert */
    server_ctx = SocketTLSContext_new_server (server_cert, server_key, ca_cert);
    SocketTLSContext_set_verify_mode (server_ctx,
                                      TLS_VERIFY_FAIL_IF_NO_PEER_CERT);

    /* Client provides cert and verifies server */
    client_ctx = SocketTLSContext_new_client (ca_cert);
    SocketTLSContext_load_certificate (client_ctx, client_cert, client_key);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    int result = complete_handshake (client, server);

    /* mTLS should succeed with proper certs */
    ASSERT_EQ (result, 0);

    /* Verify results */
    long client_verify = SocketTLS_get_verify_result (client);
    long server_verify = SocketTLS_get_verify_result (server);

    /* X509_V_OK = 0 */
    ASSERT_EQ (client_verify, 0);
    ASSERT_EQ (server_verify, 0);
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
    remove_mtls_certs (
        ca_cert, ca_key, server_cert, server_key, client_cert, client_key);
  }
  END_TRY;
}

TEST (mtls_missing_client_cert_fails)
{
  const char *ca_cert = "test_mtls_missing_ca.crt";
  const char *ca_key = "test_mtls_missing_ca.key";
  const char *server_cert = "test_mtls_missing_server.crt";
  const char *server_key = "test_mtls_missing_server.key";
  const char *client_cert = "test_mtls_missing_client.crt";
  const char *client_key = "test_mtls_missing_client.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;
  volatile int handshake_failed = 0;

  if (generate_mtls_certs (
          ca_cert, ca_key, server_cert, server_key, client_cert, client_key)
      != 0)
    return;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Server requires client cert */
    server_ctx = SocketTLSContext_new_server (server_cert, server_key, ca_cert);
    SocketTLSContext_set_verify_mode (server_ctx,
                                      TLS_VERIFY_FAIL_IF_NO_PEER_CERT);

    /* Client does NOT provide cert */
    client_ctx = SocketTLSContext_new_client (ca_cert);
    /* No SocketTLSContext_load_certificate call */

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Handshake should fail because client has no cert */
    /* Either returns -1 or raises an exception */
    TRY
    {
      int result = complete_handshake (client, server);
      if (result != 0)
        handshake_failed = 1;
    }
    EXCEPT (SocketTLS_Failed)
    {
      handshake_failed = 1;
    }
    EXCEPT (SocketTLS_HandshakeFailed)
    {
      handshake_failed = 1;
    }
    END_TRY;

    ASSERT_EQ (handshake_failed, 1); /* Should have failed */
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
    remove_mtls_certs (
        ca_cert, ca_key, server_cert, server_key, client_cert, client_key);
  }
  END_TRY;
}

/* ==================== Certificate Info Tests ==================== */

TEST (mtls_get_peer_cert_info)
{
  const char *ca_cert = "test_mtls_info_ca.crt";
  const char *ca_key = "test_mtls_info_ca.key";
  const char *server_cert = "test_mtls_info_server.crt";
  const char *server_key = "test_mtls_info_server.key";
  const char *client_cert = "test_mtls_info_client.crt";
  const char *client_key = "test_mtls_info_client.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_mtls_certs (
          ca_cert, ca_key, server_cert, server_key, client_cert, client_key)
      != 0)
    return;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    server_ctx = SocketTLSContext_new_server (server_cert, server_key, ca_cert);
    SocketTLSContext_set_verify_mode (server_ctx,
                                      TLS_VERIFY_FAIL_IF_NO_PEER_CERT);

    client_ctx = SocketTLSContext_new_client (ca_cert);
    SocketTLSContext_load_certificate (client_ctx, client_cert, client_key);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Get peer certificate info */
    SocketTLS_CertInfo info;
    int result = SocketTLS_get_peer_cert_info (server, &info);

    if (result == 0)
      {
        /* Should have client's CN */
        ASSERT (strlen (info.subject) > 0);
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
    remove_mtls_certs (
        ca_cert, ca_key, server_cert, server_key, client_cert, client_key);
  }
  END_TRY;
}

/* ==================== Verify Callback Tests ==================== */

static int callback_call_count = 0;

static int
test_verify_callback (int preverify_ok,
                      X509_STORE_CTX *x509_ctx,
                      SocketTLSContext_T tls_ctx,
                      Socket_T socket,
                      void *user_data)
{
  (void)x509_ctx;
  (void)tls_ctx;
  (void)socket;
  (void)user_data;

  callback_call_count++;
  return preverify_ok; /* Don't modify verification result */
}

TEST (mtls_custom_verify_callback)
{
  const char *ca_cert = "test_mtls_cb_ca.crt";
  const char *ca_key = "test_mtls_cb_ca.key";
  const char *server_cert = "test_mtls_cb_server.crt";
  const char *server_key = "test_mtls_cb_server.key";
  const char *client_cert = "test_mtls_cb_client.crt";
  const char *client_key = "test_mtls_cb_client.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_mtls_certs (
          ca_cert, ca_key, server_cert, server_key, client_cert, client_key)
      != 0)
    return;

  callback_call_count = 0;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Server with custom verify callback */
    server_ctx = SocketTLSContext_new_server (server_cert, server_key, ca_cert);
    SocketTLSContext_set_verify_mode (server_ctx, TLS_VERIFY_PEER);
    SocketTLSContext_set_verify_callback (
        server_ctx, test_verify_callback, NULL);

    client_ctx = SocketTLSContext_new_client (ca_cert);
    SocketTLSContext_load_certificate (client_ctx, client_cert, client_key);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    complete_handshake (client, server);

    /* Callback should have been called */
    ASSERT (callback_call_count > 0);
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
    remove_mtls_certs (
        ca_cert, ca_key, server_cert, server_key, client_cert, client_key);
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

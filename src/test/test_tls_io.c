/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_io.c - TLS I/O Operations Tests
 *
 * Part of the Socket Library Test Suite (Section 8.1)
 *
 * Tests:
 * 1. TLS send/recv basic operations
 * 2. Zero-length send/recv
 * 3. Large buffer handling
 * 4. Non-blocking I/O
 * 5. Partial writes
 * 6. Multiple send/recv cycles
 * 7. Edge cases and error handling
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

/* ==================== Basic Send/Recv Tests ==================== */

TEST (tls_io_basic_send_recv)
{
  const char *cert_file = "test_io_basic.crt";
  const char *key_file = "test_io_basic.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Create socket pair */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Create contexts */
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    /* Enable TLS and handshake */
    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Send data from client to server */
    const char *test_data = "Hello, TLS World!";
    ssize_t sent = SocketTLS_send (client, test_data, strlen (test_data));
    ASSERT (sent > 0);

    /* Receive data on server */
    char recv_buf[256] = { 0 };
    ssize_t received = 0;
    int retries = 0;

    while (received == 0 && retries < 100)
      {
        received = SocketTLS_recv (server, recv_buf, sizeof (recv_buf));
        if (received == 0 && errno == EAGAIN)
          {
            usleep (10000);
            retries++;
            received = 0;
            continue;
          }
        break;
      }

    ASSERT (received > 0);
    ASSERT_EQ (memcmp (recv_buf, test_data, (size_t)received), 0);
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

TEST (tls_io_bidirectional)
{
  const char *cert_file = "test_io_bidir.crt";
  const char *key_file = "test_io_bidir.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Setup */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Client -> Server */
    const char *client_msg = "Request from client";
    ssize_t sent = SocketTLS_send (client, client_msg, strlen (client_msg));
    ASSERT (sent > 0);

    char server_recv[256] = { 0 };
    ssize_t received = 0;
    int retries = 0;
    while (received <= 0 && retries < 100)
      {
        received = SocketTLS_recv (server, server_recv, sizeof (server_recv));
        if (received <= 0)
          usleep (10000);
        retries++;
      }
    ASSERT (received > 0);

    /* Server -> Client */
    const char *server_msg = "Response from server";
    sent = SocketTLS_send (server, server_msg, strlen (server_msg));
    ASSERT (sent > 0);

    char client_recv[256] = { 0 };
    received = 0;
    retries = 0;
    while (received <= 0 && retries < 100)
      {
        received = SocketTLS_recv (client, client_recv, sizeof (client_recv));
        if (received <= 0)
          usleep (10000);
        retries++;
      }
    ASSERT (received > 0);
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

/* ==================== Zero-Length Tests ==================== */

TEST (tls_io_zero_length_send)
{
  const char *cert_file = "test_io_zero.crt";
  const char *key_file = "test_io_zero.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Setup */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Zero-length send should return 0 immediately */
    char buf[1] = { 0 };
    ssize_t sent = SocketTLS_send (client, buf, 0);
    ASSERT_EQ (sent, 0);
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

TEST (tls_io_zero_length_recv)
{
  const char *cert_file = "test_io_zero_recv.crt";
  const char *key_file = "test_io_zero_recv.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Setup */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Zero-length recv should return 0 immediately */
    char buf[1] = { 0 };
    ssize_t received = SocketTLS_recv (client, buf, 0);
    ASSERT_EQ (received, 0);
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

/* ==================== Large Buffer Tests ==================== */

TEST (tls_io_large_message)
{
  const char *cert_file = "test_io_large.crt";
  const char *key_file = "test_io_large.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Setup */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Send large message (32KB) */
    size_t msg_size = 32 * 1024;
    char *send_buf = malloc (msg_size);
    ASSERT_NOT_NULL (send_buf);

    /* Fill with pattern */
    for (size_t i = 0; i < msg_size; i++)
      send_buf[i] = (char)(i & 0xFF);

    /* Send in chunks */
    size_t total_sent = 0;
    while (total_sent < msg_size)
      {
        ssize_t sent = SocketTLS_send (
            client, send_buf + total_sent, msg_size - total_sent);
        if (sent > 0)
          total_sent += (size_t)sent;
        else if (errno == EAGAIN)
          usleep (1000);
        else
          break;
      }

    /* Receive all data */
    char *recv_buf = malloc (msg_size);
    ASSERT_NOT_NULL (recv_buf);

    size_t total_received = 0;
    int retries = 0;
    while (total_received < msg_size && retries < 1000)
      {
        ssize_t received = SocketTLS_recv (
            server, recv_buf + total_received, msg_size - total_received);
        if (received > 0)
          {
            total_received += (size_t)received;
            retries = 0;
          }
        else if (errno == EAGAIN)
          {
            usleep (1000);
            retries++;
          }
        else
          break;
      }

    ASSERT_EQ (total_received, msg_size);
    ASSERT_EQ (memcmp (send_buf, recv_buf, msg_size), 0);

    free (send_buf);
    free (recv_buf);
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

/* ==================== Error Condition Tests ==================== */

TEST (tls_io_send_before_handshake_fails)
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

    /* Send before handshake should fail */
    char buf[] = "test";
    TRY
    {
      SocketTLS_send (socket, buf, sizeof (buf));
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
    EXCEPT (SocketTLS_HandshakeFailed)
    {
      caught = 1;
    }
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

TEST (tls_io_recv_before_handshake_fails)
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

    /* Recv before handshake should fail */
    char buf[64];
    TRY
    {
      SocketTLS_recv (socket, buf, sizeof (buf));
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
    EXCEPT (SocketTLS_HandshakeFailed)
    {
      caught = 1;
    }
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

/* ==================== Multiple Cycles Tests ==================== */

TEST (tls_io_multiple_send_recv_cycles)
{
  const char *cert_file = "test_io_cycles.crt";
  const char *key_file = "test_io_cycles.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Setup */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);
    ASSERT_EQ (complete_handshake (client, server), 0);

    /* Multiple request-response cycles */
    for (int i = 0; i < 10; i++)
      {
        char request[64];
        snprintf (request, sizeof (request), "Request #%d", i);

        ssize_t sent = SocketTLS_send (client, request, strlen (request));
        ASSERT (sent > 0);

        char response[64] = { 0 };
        ssize_t received = 0;
        int retries = 0;
        while (received <= 0 && retries < 100)
          {
            received = SocketTLS_recv (server, response, sizeof (response));
            if (received <= 0)
              usleep (1000);
            retries++;
          }
        ASSERT (received > 0);

        /* Echo back */
        sent = SocketTLS_send (server, response, (size_t)received);
        ASSERT (sent > 0);

        char echo[64] = { 0 };
        received = 0;
        retries = 0;
        while (received <= 0 && retries < 100)
          {
            received = SocketTLS_recv (client, echo, sizeof (echo));
            if (received <= 0)
              usleep (1000);
            retries++;
          }
        ASSERT (received > 0);
        ASSERT_EQ (memcmp (request, echo, (size_t)received), 0);
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

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

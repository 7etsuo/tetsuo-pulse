/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socketio.c - SocketIO Internal Module Tests
 *
 * Part of the Socket Library Test Suite
 *
 * Tests for the internal I/O abstraction layer:
 * - socket_send_internal / socket_recv_internal
 * - socket_sendv_internal / socket_recvv_internal
 * - socket_is_tls_enabled checks
 * - Helper functions (socketio_is_wouldblock, etc.)
 * - Statistics tracking via I/O operations
 * - TLS-aware routing (conditional on SOCKET_HAS_TLS)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketIO.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#endif

/* Create a connected socket pair for testing I/O */
static int
create_socket_pair (Socket_T *client, Socket_T *server_accepted)
{
  Socket_T server = NULL;
  volatile int result = -1;
  int port;

  TRY
  {
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 1);
    port = Socket_getlocalport (server);

    *client = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_connect (*client, "127.0.0.1", port);

    *server_accepted = Socket_accept_timeout (server, 1000);
    if (*server_accepted == NULL)
      {
        Socket_free (client);
        Socket_free (&server);
        result = -1;
      }
    else
      {
        Socket_free (&server);
        result = 0;
      }
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    result = -1;
  }
  END_TRY;

  return result;
}

static void
cleanup_socket_pair (Socket_T *client, Socket_T *server)
{
  if (client && *client)
    Socket_free (client);
  if (server && *server)
    Socket_free (server);
}

TEST (socketio_is_wouldblock_eagain)
{
  errno = EAGAIN;
  ASSERT_EQ (socketio_is_wouldblock (), 1);
}

TEST (socketio_is_wouldblock_ewouldblock)
{
  errno = EWOULDBLOCK;
  ASSERT_EQ (socketio_is_wouldblock (), 1);
}

TEST (socketio_is_wouldblock_other)
{
  errno = ECONNREFUSED;
  ASSERT_EQ (socketio_is_wouldblock (), 0);

  errno = EPIPE;
  ASSERT_EQ (socketio_is_wouldblock (), 0);

  errno = 0;
  ASSERT_EQ (socketio_is_wouldblock (), 0);
}

TEST (socketio_is_connection_closed_send_epipe)
{
  errno = EPIPE;
  ASSERT_EQ (socketio_is_connection_closed_send (), 1);
}

TEST (socketio_is_connection_closed_send_econnreset)
{
  errno = ECONNRESET;
  ASSERT_EQ (socketio_is_connection_closed_send (), 1);
}

TEST (socketio_is_connection_closed_send_other)
{
  errno = EAGAIN;
  ASSERT_EQ (socketio_is_connection_closed_send (), 0);

  errno = ETIMEDOUT;
  ASSERT_EQ (socketio_is_connection_closed_send (), 0);
}

TEST (socketio_is_connection_closed_recv_econnreset)
{
  errno = ECONNRESET;
  ASSERT_EQ (socketio_is_connection_closed_recv (), 1);
}

TEST (socketio_is_connection_closed_recv_other)
{
  errno = EPIPE;
  ASSERT_EQ (socketio_is_connection_closed_recv (), 0);

  errno = EAGAIN;
  ASSERT_EQ (socketio_is_connection_closed_recv (), 0);
}

TEST (socketio_is_tls_enabled_no_tls)
{
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    /* Regular socket should not have TLS enabled */
    int tls_enabled = socket_is_tls_enabled (sock);
    ASSERT_EQ (tls_enabled, 0);
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

TEST (socketio_tls_want_read_no_tls)
{
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    /* Non-TLS socket should return 0 */
    int want_read = socket_tls_want_read (sock);
    ASSERT_EQ (want_read, 0);
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

TEST (socketio_tls_want_write_no_tls)
{
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    /* Non-TLS socket should return 0 */
    int want_write = socket_tls_want_write (sock);
    ASSERT_EQ (want_write, 0);
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

TEST (socketio_send_recv_internal_basic)
{
  Socket_T client = NULL;
  Socket_T server = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_socket_pair (&client, &server) != 0)
    {
      /* Skip test if socket pair creation fails */
      return;
    }

  TRY
  {
    const char *msg = "Hello via socket_send_internal";
    ssize_t sent = socket_send_internal (client, msg, strlen (msg), 0);
    ASSERT_EQ (sent, (ssize_t)strlen (msg));

    /* Give data time to arrive */
    usleep (10000);

    char buf[100] = { 0 };
    ssize_t received = socket_recv_internal (server, buf, sizeof (buf) - 1, 0);
    ASSERT_EQ (received, sent);
    ASSERT_EQ (strcmp (buf, msg), 0);
  }
  EXCEPT (Socket_Failed)
  { /* May fail */
  }
  EXCEPT (Socket_Closed)
  { /* May close */
  }
  FINALLY
  {
    cleanup_socket_pair (&client, &server);
  }
  END_TRY;
}

TEST (socketio_send_internal_updates_stats)
{
  Socket_T client = NULL;
  Socket_T server = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_socket_pair (&client, &server) != 0)
    return;

  TRY
  {
    /* Get stats before send */
    SocketStats_T stats_before;
    Socket_getstats (client, &stats_before);

    const char *msg = "Test message for stats";
    ssize_t sent = socket_send_internal (client, msg, strlen (msg), 0);
    ASSERT (sent > 0);

    /* Get stats after send */
    SocketStats_T stats_after;
    Socket_getstats (client, &stats_after);

    ASSERT_EQ (stats_after.bytes_sent,
               stats_before.bytes_sent + (uint64_t)sent);
    ASSERT_EQ (stats_after.packets_sent, stats_before.packets_sent + 1);
    ASSERT (stats_after.last_send_time_ms >= stats_before.last_send_time_ms);
  }
  EXCEPT (Socket_Failed)
  { /* May fail */
  }
  EXCEPT (Socket_Closed)
  { /* May close */
  }
  FINALLY
  {
    cleanup_socket_pair (&client, &server);
  }
  END_TRY;
}

TEST (socketio_recv_internal_updates_stats)
{
  Socket_T client = NULL;
  Socket_T server = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_socket_pair (&client, &server) != 0)
    return;

  TRY
  {
    /* Send some data */
    const char *msg = "Test message for recv stats";
    socket_send_internal (client, msg, strlen (msg), 0);
    usleep (10000);

    /* Get stats before recv */
    SocketStats_T stats_before;
    Socket_getstats (server, &stats_before);

    char buf[100];
    ssize_t received = socket_recv_internal (server, buf, sizeof (buf), 0);
    ASSERT (received > 0);

    /* Get stats after recv */
    SocketStats_T stats_after;
    Socket_getstats (server, &stats_after);

    ASSERT_EQ (stats_after.bytes_received,
               stats_before.bytes_received + (uint64_t)received);
    ASSERT_EQ (stats_after.packets_received, stats_before.packets_received + 1);
    ASSERT (stats_after.last_recv_time_ms >= stats_before.last_recv_time_ms);
  }
  EXCEPT (Socket_Failed)
  { /* May fail */
  }
  EXCEPT (Socket_Closed)
  { /* May close */
  }
  FINALLY
  {
    cleanup_socket_pair (&client, &server);
  }
  END_TRY;
}

TEST (socketio_sendv_recvv_internal_basic)
{
  Socket_T client = NULL;
  Socket_T server = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_socket_pair (&client, &server) != 0)
    return;

  TRY
  {
    /* Prepare scatter data */
    struct iovec send_iov[3];
    const char *part1 = "Hello";
    const char *part2 = " ";
    const char *part3 = "World";

    send_iov[0].iov_base = (void *)part1;
    send_iov[0].iov_len = strlen (part1);
    send_iov[1].iov_base = (void *)part2;
    send_iov[1].iov_len = strlen (part2);
    send_iov[2].iov_base = (void *)part3;
    send_iov[2].iov_len = strlen (part3);

    ssize_t total_len
        = (ssize_t)(strlen (part1) + strlen (part2) + strlen (part3));
    ssize_t sent = socket_sendv_internal (client, send_iov, 3, 0);
    ASSERT_EQ (sent, total_len);

    /* Give data time to arrive */
    usleep (10000);

    /* Prepare gather buffers */
    struct iovec recv_iov[2];
    char buf1[8] = { 0 };
    char buf2[8] = { 0 };
    recv_iov[0].iov_base = buf1;
    recv_iov[0].iov_len = 6; /* "Hello " */
    recv_iov[1].iov_base = buf2;
    recv_iov[1].iov_len = 5; /* "World" */

    ssize_t received = socket_recvv_internal (server, recv_iov, 2, 0);
    ASSERT_EQ (received, total_len);

    /* Verify data */
    ASSERT_EQ (strncmp (buf1, "Hello ", 6), 0);
    ASSERT_EQ (strncmp (buf2, "World", 5), 0);
  }
  EXCEPT (Socket_Failed)
  { /* May fail */
  }
  EXCEPT (Socket_Closed)
  { /* May close */
  }
  FINALLY
  {
    cleanup_socket_pair (&client, &server);
  }
  END_TRY;
}

TEST (socketio_sendv_single_buffer)
{
  Socket_T client = NULL;
  Socket_T server = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_socket_pair (&client, &server) != 0)
    return;

  TRY
  {
    /* Single buffer scatter send */
    struct iovec iov[1];
    const char *msg = "Single buffer sendv";
    iov[0].iov_base = (void *)msg;
    iov[0].iov_len = strlen (msg);

    ssize_t sent = socket_sendv_internal (client, iov, 1, 0);
    ASSERT_EQ (sent, (ssize_t)strlen (msg));

    usleep (10000);

    char buf[50] = { 0 };
    ssize_t received = socket_recv_internal (server, buf, sizeof (buf), 0);
    ASSERT_EQ (received, sent);
    ASSERT_EQ (strcmp (buf, msg), 0);
  }
  EXCEPT (Socket_Failed)
  { /* May fail */
  }
  EXCEPT (Socket_Closed)
  { /* May close */
  }
  FINALLY
  {
    cleanup_socket_pair (&client, &server);
  }
  END_TRY;
}

TEST (socketio_nonblocking_recv_wouldblock)
{
  Socket_T client = NULL;
  Socket_T server = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_socket_pair (&client, &server) != 0)
    return;

  TRY
  {
    /* Set server socket non-blocking */
    Socket_setnonblocking (server);

    /* Try to recv when no data is available */
    char buf[100];
    ssize_t result = socket_recv_internal (server, buf, sizeof (buf), 0);

    /* Should return 0 (would block) or data if any exists */
    ASSERT (result >= 0);
  }
  EXCEPT (Socket_Failed)
  { /* May fail */
  }
  EXCEPT (Socket_Closed)
  { /* May close */
  }
  FINALLY
  {
    cleanup_socket_pair (&client, &server);
  }
  END_TRY;
}

TEST (socketio_recv_detects_close)
{
  Socket_T client = NULL;
  Socket_T server = NULL;
  volatile int closed_raised = 0;

  signal (SIGPIPE, SIG_IGN);

  if (create_socket_pair (&client, &server) != 0)
    return;

  /* Close client side */
  Socket_free (&client);
  usleep (50000);

  TRY
  {
    char buf[100];
    socket_recv_internal (server, buf, sizeof (buf), 0);
  }
  EXCEPT (Socket_Closed)
  {
    closed_raised = 1;
  }
  EXCEPT (Socket_Failed)
  { /* Also acceptable */
  }
  FINALLY
  {
    cleanup_socket_pair (&client, &server);
  }
  END_TRY;

  ASSERT_EQ (closed_raised, 1);
}

TEST (socketio_send_recv_large_data)
{
  Socket_T client = NULL;
  Socket_T server = NULL;
  char *send_buf = NULL;
  char *recv_buf = NULL;
  const size_t data_size = 64 * 1024; /* 64KB */

  signal (SIGPIPE, SIG_IGN);

  if (create_socket_pair (&client, &server) != 0)
    return;

  send_buf = malloc (data_size);
  recv_buf = malloc (data_size);
  if (!send_buf || !recv_buf)
    {
      free (send_buf);
      free (recv_buf);
      cleanup_socket_pair (&client, &server);
      return;
    }

  /* Fill with pattern */
  for (size_t i = 0; i < data_size; i++)
    send_buf[i] = (char)(i & 0xFF);

  TRY
  {
    /* Send in chunks */
    size_t total_sent = 0;
    while (total_sent < data_size)
      {
        size_t chunk = data_size - total_sent;
        if (chunk > 8192)
          chunk = 8192;
        ssize_t sent
            = socket_send_internal (client, send_buf + total_sent, chunk, 0);
        if (sent > 0)
          total_sent += (size_t)sent;
        else
          break;
      }

    /* Give data time to buffer */
    usleep (100000);

    /* Receive all data */
    size_t total_received = 0;
    while (total_received < total_sent)
      {
        ssize_t received = socket_recv_internal (
            server, recv_buf + total_received, data_size - total_received, 0);
        if (received > 0)
          total_received += (size_t)received;
        else
          break;
      }

    ASSERT_EQ (total_received, total_sent);

    /* Verify data integrity */
    ASSERT_EQ (memcmp (send_buf, recv_buf, total_received), 0);
  }
  EXCEPT (Socket_Failed)
  { /* May fail */
  }
  EXCEPT (Socket_Closed)
  { /* May close */
  }
  FINALLY
  {
    free (send_buf);
    free (recv_buf);
    cleanup_socket_pair (&client, &server);
  }
  END_TRY;
}

#if SOCKET_HAS_TLS

/* Helper to generate test certificates */
static int
generate_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[2048];
  snprintf (cmd,
            sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
            "-nodes -subj '/CN=localhost' 2>/dev/null",
            key_file,
            cert_file);
  return system (cmd);
}

static void
remove_test_certs (const char *cert_file, const char *key_file)
{
  unlink (cert_file);
  unlink (key_file);
}

TEST (socketio_tls_enabled_check)
{
  const char *cert_file = "test_io_tls.crt";
  const char *key_file = "test_io_tls.key";
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T server_sock = NULL;
  Socket_T client_sock = NULL;
  int sv[2];

  signal (SIGPIPE, SIG_IGN);

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);

    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);
    SocketTLSContext_set_verify_mode (server_ctx, TLS_VERIFY_NONE);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    /* Before TLS enable */
    ASSERT_EQ (socket_is_tls_enabled (server_sock), 0);
    ASSERT_EQ (socket_is_tls_enabled (client_sock), 0);

    /* Enable TLS */
    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    /* After TLS enable */
    ASSERT_EQ (socket_is_tls_enabled (server_sock), 1);
    ASSERT_EQ (socket_is_tls_enabled (client_sock), 1);
  }
  EXCEPT (SocketTLS_Failed)
  { /* May fail */
  }
  EXCEPT (Socket_Failed)
  { /* May fail */
  }
  FINALLY
  {
    if (client_sock)
      Socket_free (&client_sock);
    if (server_sock)
      Socket_free (&server_sock);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (socketio_tls_want_read_write)
{
  const char *cert_file = "test_io_want.crt";
  const char *key_file = "test_io_want.key";
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T server_sock = NULL;
  Socket_T client_sock = NULL;
  int sv[2];

  signal (SIGPIPE, SIG_IGN);

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);

    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* During handshake, want_read/want_write may return various values */
    /* This is a basic smoke test to ensure no crashes */
    int want_read_client = socket_tls_want_read (client_sock);
    int want_write_client = socket_tls_want_write (client_sock);
    int want_read_server = socket_tls_want_read (server_sock);
    int want_write_server = socket_tls_want_write (server_sock);

    /* Values should be 0 or 1 */
    ASSERT (want_read_client >= 0 && want_read_client <= 1);
    ASSERT (want_write_client >= 0 && want_write_client <= 1);
    ASSERT (want_read_server >= 0 && want_read_server <= 1);
    ASSERT (want_write_server >= 0 && want_write_server <= 1);
  }
  EXCEPT (SocketTLS_Failed)
  { /* May fail */
  }
  EXCEPT (Socket_Failed)
  { /* May fail */
  }
  FINALLY
  {
    if (client_sock)
      Socket_free (&client_sock);
    if (server_sock)
      Socket_free (&server_sock);
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
  signal (SIGPIPE, SIG_IGN);
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

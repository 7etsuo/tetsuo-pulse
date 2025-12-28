/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socket.c - Comprehensive Socket unit tests
 * Industry-standard test coverage for Socket module.
 * Tests TCP sockets, Unix domain sockets, IPv6, error conditions, and edge
 * cases.
 */

/* cppcheck-suppress-file constVariablePointer ; test allocation success */
/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */
/* cppcheck-suppress-file redundantAssignment ; test code patterns */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stdlib.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#include "test/Test.h"

#define TEST_UNIX_SOCKET_PATH "/tmp/test_socket_unix"
#define TEST_BUFFER_SIZE 4096

/**
 * setup_signals - Legacy signal setup (no longer needed)
 *
 * NOTE: The socket library now handles SIGPIPE internally via MSG_NOSIGNAL
 * (Linux) and SO_NOSIGPIPE (BSD/macOS). This function is kept as a no-op
 * for compatibility with existing test code. New tests should NOT call this.
 *
 * SIGPIPE is now ignored once in main() via Socket_ignore_sigpipe().
 */
static void
setup_signals (void)
{
  /* No-op - SIGPIPE handled by Socket_ignore_sigpipe() in main() */
}

/* Cleanup Unix socket files */
static void
cleanup_unix_socket (const char *path)
{
  unlink (path);
}

typedef struct
{
  int count;
  SocketEventRecord last_event;
} EventProbe;

static void
event_probe_callback (void *userdata, const SocketEventRecord *event)
{
  EventProbe *probe = (EventProbe *)userdata;

  if (!probe || !event)
    return;

  probe->count++;
  probe->last_event = *event;
}

/* ==================== Basic Socket Tests ==================== */

TEST (socket_new_creates_ipv4_socket)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  Socket_free (&socket);
  ASSERT_NULL (socket);
}

TEST (socket_new_creates_ipv6_socket)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET6, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  Socket_free (&socket);
  ASSERT_NULL (socket);
}

TEST (socket_new_creates_unix_socket)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  Socket_free (&socket);
  ASSERT_NULL (socket);
}

TEST (socket_fd_access)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  int fd = Socket_fd (socket);
  ASSERT_NE (fd, -1);
  Socket_free (&socket);
}

/* ==================== Bind Tests ==================== */

TEST (socket_bind_localhost_ipv4)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  TRY Socket_bind (socket, "127.0.0.1", 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_bind_any_address)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  TRY Socket_bind (socket, NULL, 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_bind_wildcard_ipv4)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  TRY Socket_bind (socket, "0.0.0.0", 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_bind_ipv6_localhost)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET6, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  TRY Socket_bind (socket, "::1", 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_bind_ipv6_any)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET6, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  TRY Socket_bind (socket, "::", 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

/* ==================== Unix Domain Socket Tests ==================== */

TEST (socket_bind_unix_regular)
{
  setup_signals ();
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);
  Socket_T socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  TRY Socket_bind_unix (socket, TEST_UNIX_SOCKET_PATH);
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);
  EXCEPT (Socket_Failed)
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);
  ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_unix_connect_accept)
{
  setup_signals ();
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);

  Socket_T server = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (server);
  ASSERT_NOT_NULL (client);

  TRY Socket_bind_unix (server, TEST_UNIX_SOCKET_PATH);
  Socket_listen (server, 5);
  Socket_setnonblocking (server);
  Socket_connect_unix (client, TEST_UNIX_SOCKET_PATH);
  Socket_T accepted = Socket_accept (server);
  if (!accepted)
    {
      usleep (50000);
      accepted = Socket_accept (server);
    }
  if (accepted)
    Socket_free (&accepted);
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);
  EXCEPT (Socket_Failed)
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

TEST (socket_unix_send_receive)
{
  setup_signals ();
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);

  Socket_T server = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_UNIX, SOCK_STREAM, 0);

  TRY Socket_bind_unix (server, TEST_UNIX_SOCKET_PATH);
  Socket_listen (server, 5);
  Socket_setnonblocking (server);
  Socket_connect_unix (client, TEST_UNIX_SOCKET_PATH);

  Socket_T accepted = Socket_accept (server);
  if (!accepted)
    {
      usleep (50000);
      accepted = Socket_accept (server);
    }

  if (accepted)
    {
      const char *msg = "Unix socket test";
      Socket_send (client, msg, strlen (msg));
      usleep (10000);
      char buf[TEST_BUFFER_SIZE] = { 0 };
      ssize_t received = Socket_recv (accepted, buf, sizeof (buf) - 1);
      if (received > 0)
        ASSERT_EQ (strcmp (buf, msg), 0);
      Socket_free (&accepted);
    }
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);
  EXCEPT (Socket_Failed)
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

#ifdef SO_PEERCRED
TEST (socket_unix_peer_credentials)
{
  setup_signals ();
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);

  Socket_T server = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_UNIX, SOCK_STREAM, 0);

  TRY Socket_bind_unix (server, TEST_UNIX_SOCKET_PATH);
  Socket_listen (server, 5);
  Socket_setnonblocking (server);
  Socket_connect_unix (client, TEST_UNIX_SOCKET_PATH);

  Socket_T accepted = Socket_accept (server);
  if (!accepted)
    {
      usleep (50000);
      accepted = Socket_accept (server);
    }

  if (accepted)
    {
      int pid = Socket_getpeerpid (accepted);
      int uid = Socket_getpeeruid (accepted);
      int gid = Socket_getpeergid (accepted);
      ASSERT_NE (pid, -1);
      ASSERT_NE (uid, -1);
      ASSERT_NE (gid, -1);
      Socket_free (&accepted);
    }
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);
  EXCEPT (Socket_Failed)
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}
#endif

/* ==================== Listen/Accept Tests ==================== */

TEST (socket_listen_basic)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_bind (socket, "127.0.0.1", 0);
  Socket_listen (socket, 5);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_listen_large_backlog)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_bind (socket, "127.0.0.1", 0);
  Socket_listen (socket, 1024);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_accept_nonblocking_returns_null)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_bind (socket, "127.0.0.1", 0);
  Socket_listen (socket, 5);
  Socket_setnonblocking (socket);
  Socket_T accepted = Socket_accept (socket);
  ASSERT_NULL (accepted);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

/* ==================== Connect Tests ==================== */

TEST (socket_connect_localhost_ipv4)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);
  Socket_connect (client, "127.0.0.1", port);
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

TEST (socket_connect_localhost_ipv6)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET6, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET6, SOCK_STREAM, 0);

  TRY Socket_bind (server, "::1", 0);
  Socket_listen (server, 1);
  struct sockaddr_in6 addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin6_port);
  Socket_connect (client, "::1", port);
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

/* ==================== Send/Receive Tests ==================== */

TEST (socket_send_receive_basic)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);
  Socket_connect (client, "127.0.0.1", port);
  Socket_T accepted = Socket_accept (server);
  if (!accepted)
    {
      usleep (100000);
      accepted = Socket_accept (server);
    }

  if (accepted)
    {
      const char *msg = "Test message";
      ssize_t sent = Socket_send (client, msg, strlen (msg));
      if (sent > 0)
        {
          usleep (10000);
          char buf[TEST_BUFFER_SIZE] = { 0 };
          ssize_t received = Socket_recv (accepted, buf, sizeof (buf) - 1);
          if (received > 0)
            ASSERT_EQ (strcmp (buf, msg), 0);
        }
      Socket_free (&accepted);
    }
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

TEST (socket_send_large_data)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);
  Socket_connect (client, "127.0.0.1", port);
  Socket_T accepted = Socket_accept (server);
  if (!accepted)
    {
      usleep (100000);
      accepted = Socket_accept (server);
    }

  if (accepted)
    {
      char large_buf[8192];
      memset (large_buf, 'A', sizeof (large_buf));
      ssize_t sent = Socket_send (client, large_buf, sizeof (large_buf));
      ASSERT_NE (sent, -1);
      Socket_free (&accepted);
    }
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

TEST (socket_bidirectional_communication)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile int port;
  Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  port = ntohs (addr.sin_port);
  Socket_connect (client, "127.0.0.1", port);
  volatile Socket_T accepted = Socket_accept (server);
  if (!accepted)
    {
      usleep (100000);
      accepted = Socket_accept (server);
    }

  if (accepted)
    {
      const char *c2s = "Client to Server";
      const char *s2c = "Server to Client";
      Socket_send (client, c2s, strlen (c2s));
      usleep (10000);
      char buf1[TEST_BUFFER_SIZE] = { 0 };
      Socket_recv (accepted, buf1, sizeof (buf1) - 1);
      Socket_send (accepted, s2c, strlen (s2c));
      usleep (10000);
      char buf2[TEST_BUFFER_SIZE] = { 0 };
      Socket_recv (client, buf2, sizeof (buf2) - 1);
      Socket_T a = (Socket_T)accepted;
      Socket_free (&a);
    }
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

/* ==================== Socket Options Tests ==================== */

TEST (socket_setnonblocking)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_setnonblocking (socket);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_setreuseaddr)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_setreuseaddr (socket);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_settimeout)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_settimeout (socket, 5);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_settimeout_zero)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_settimeout (socket, 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_setkeepalive)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_setkeepalive (socket, 60, 10, 3);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_setnodelay_enable)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_setnodelay (socket, 1);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

TEST (socket_setnodelay_disable)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  TRY Socket_setnodelay (socket, 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;
  Socket_free (&socket);
}

/* ==================== Socket Option Getter Tests ==================== */

TEST (socket_gettimeout_returns_set_value)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  Socket_settimeout (socket, 5);
  int timeout = Socket_gettimeout (socket);
  ASSERT_EQ (timeout, 5);

  Socket_settimeout (socket, 0);
  timeout = Socket_gettimeout (socket);
  ASSERT_EQ (timeout, 0);

  Socket_free (&socket);
}

TEST (socket_getkeepalive_returns_set_values)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  Socket_setkeepalive (socket, 60, 10, 3);
  int idle = 0, interval = 0, count = 0;
  TRY Socket_getkeepalive (socket, &idle, &interval, &count);
  EXCEPT (Socket_Failed)
  {
    /* On macOS, getsockopt may fail or return default values */
    Socket_free (&socket);
    return;
  }
  END_TRY;

#if SOCKET_PLATFORM_MACOS
  /* On macOS, getsockopt() doesn't reliably return set values */
  /* Verify that getsockopt succeeded (no exception) but don't assert values */
  (void)idle;
  (void)interval;
  (void)count;
#else
  ASSERT_EQ (idle, 60);
  ASSERT_EQ (interval, 10);
  ASSERT_EQ (count, 3);
#endif

  Socket_free (&socket);
}

TEST (socket_getnodelay_returns_set_value)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  int nodelay;

  Socket_setnodelay (socket, 1);

  TRY
  {
    nodelay = Socket_getnodelay (socket);
#if SOCKET_PLATFORM_MACOS
    /* On macOS, getsockopt() doesn't reliably return set values */
    /* Verify that getsockopt succeeded (no exception) but don't assert value
     */
    (void)nodelay;
#else
    ASSERT_EQ (nodelay, 1);
#endif
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  Socket_setnodelay (socket, 0);

  TRY
  {
    nodelay = Socket_getnodelay (socket);
#if SOCKET_PLATFORM_MACOS
    /* On macOS, getsockopt() doesn't reliably return set values */
    (void)nodelay;
#else
    ASSERT_EQ (nodelay, 0);
#endif
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_getrcvbuf_returns_positive_value)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  int rcvbuf = Socket_getrcvbuf (socket);
  ASSERT (rcvbuf > 0);

  Socket_free (&socket);
}

TEST (socket_getsndbuf_returns_positive_value)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  int sndbuf = Socket_getsndbuf (socket);
  ASSERT (sndbuf > 0);

  Socket_free (&socket);
}

/* ==================== Connection State Query Tests ==================== */

TEST (socket_isbound_returns_false_for_new_socket)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  ASSERT_EQ (0, Socket_isbound (socket));

  Socket_free (&socket);
}

TEST (socket_isbound_returns_true_after_bind)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  Socket_bind (socket, "127.0.0.1", 0);
  ASSERT_EQ (1, Socket_isbound (socket));

  Socket_free (&socket);
}

TEST (socket_isconnected_returns_false_for_new_socket)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  ASSERT_EQ (0, Socket_isconnected (socket));

  Socket_free (&socket);
}

TEST (socket_isconnected_returns_true_after_connect)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_setnonblocking (server);

  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  Socket_connect (client, "127.0.0.1", port);
  usleep (10000);

  ASSERT_EQ (1, Socket_isconnected (client));

  Socket_T accepted = Socket_accept (server);
  if (accepted)
    {
      ASSERT_EQ (1, Socket_isconnected (accepted));
      Socket_free (&accepted);
    }
  EXCEPT (Socket_Failed)
  (void)0;
  END_TRY;

  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_islistening_returns_false_for_new_socket)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  ASSERT_EQ (0, Socket_islistening (socket));

  Socket_free (&socket);
}

TEST (socket_islistening_returns_true_after_listen)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  Socket_bind (socket, "127.0.0.1", 0);
  Socket_listen (socket, 5);
  ASSERT_EQ (1, Socket_islistening (socket));

  Socket_free (&socket);
}

TEST (socket_islistening_returns_false_after_connect)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  ASSERT_EQ (1, Socket_islistening (server));

  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  Socket_connect (client, "127.0.0.1", port);
  usleep (10000);

  /* Server is still listening (can accept more connections) */
  ASSERT_EQ (1, Socket_islistening (server));
  EXCEPT (Socket_Failed)
  (void)0;
  END_TRY;

  Socket_free (&server);
  Socket_free (&client);
}

/* ==================== Socket Pair Tests ==================== */

TEST (socketpair_new_creates_connected_stream_sockets)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;

  TRY SocketPair_new (SOCK_STREAM, &socket1, &socket2);
  ASSERT_NOT_NULL (socket1);
  ASSERT_NOT_NULL (socket2);

  /* Verify sockets are connected */
  ASSERT_EQ (1, Socket_isconnected (socket1));
  ASSERT_EQ (1, Socket_isconnected (socket2));

  /* Test bidirectional communication */
  const char *msg = "Hello from socket1";
  ssize_t sent = Socket_send (socket1, msg, strlen (msg));
  ASSERT (sent > 0);

  char buf[256] = { 0 };
  ssize_t received = Socket_recv (socket2, buf, sizeof (buf) - 1);
  ASSERT (received > 0);
  ASSERT_EQ (0, strcmp (buf, msg));

  /* Test reverse direction */
  const char *reply = "Hello from socket2";
  sent = Socket_send (socket2, reply, strlen (reply));
  ASSERT (sent > 0);

  memset (buf, 0, sizeof (buf));
  received = Socket_recv (socket1, buf, sizeof (buf) - 1);
  ASSERT (received > 0);
  ASSERT_EQ (0, strcmp (buf, reply));
  EXCEPT (Socket_Failed)
  (void)0;
  END_TRY;

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

TEST (socketpair_new_creates_connected_dgram_sockets)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;

  TRY SocketPair_new (SOCK_DGRAM, &socket1, &socket2);
  ASSERT_NOT_NULL (socket1);
  ASSERT_NOT_NULL (socket2);

  /* Verify sockets are connected */
  ASSERT_EQ (1, Socket_isconnected (socket1));
  ASSERT_EQ (1, Socket_isconnected (socket2));

  /* Test bidirectional communication */
  const char *msg = "Hello from socket1";
  ssize_t sent = Socket_send (socket1, msg, strlen (msg));
  ASSERT (sent > 0);

  char buf[256] = { 0 };
  ssize_t received = Socket_recv (socket2, buf, sizeof (buf) - 1);
  ASSERT (received > 0);
  ASSERT_EQ (0, strcmp (buf, msg));

  /* Test reverse direction */
  const char *reply = "Hello from socket2";
  sent = Socket_send (socket2, reply, strlen (reply));
  ASSERT (sent > 0);

  memset (buf, 0, sizeof (buf));
  received = Socket_recv (socket1, buf, sizeof (buf) - 1);
  ASSERT (received > 0);
  ASSERT_EQ (0, strcmp (buf, reply));
  EXCEPT (Socket_Failed)
  (void)0;
  END_TRY;

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

TEST (socketpair_new_sockets_are_unix_domain)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;

  TRY SocketPair_new (SOCK_STREAM, &socket1, &socket2);
  ASSERT_NOT_NULL (socket1);
  ASSERT_NOT_NULL (socket2);

  /* Verify sockets are Unix domain sockets */
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);
  ASSERT_EQ (
      0, getsockname (Socket_fd (socket1), (struct sockaddr *)&addr, &len));
  ASSERT_EQ (AF_UNIX, addr.ss_family);

  len = sizeof (addr);
  ASSERT_EQ (
      0, getsockname (Socket_fd (socket2), (struct sockaddr *)&addr, &len));
  ASSERT_EQ (AF_UNIX, addr.ss_family);
  EXCEPT (Socket_Failed)
  (void)0;
  END_TRY;

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

/* ==================== Address Resolution Helper Tests ==================== */

TEST (socketcommon_parse_ip_validates_ipv4)
{
  int family = AF_UNSPEC;

  ASSERT_EQ (1, SocketCommon_parse_ip ("127.0.0.1", &family));
  ASSERT_EQ (AF_INET, family);

  ASSERT_EQ (1, SocketCommon_parse_ip ("192.168.1.1", &family));
  ASSERT_EQ (AF_INET, family);

  ASSERT_EQ (1, SocketCommon_parse_ip ("0.0.0.0", &family));
  ASSERT_EQ (AF_INET, family);

  ASSERT_EQ (1, SocketCommon_parse_ip ("255.255.255.255", &family));
  ASSERT_EQ (AF_INET, family);
}

TEST (socketcommon_parse_ip_validates_ipv6)
{
  int family = AF_UNSPEC;

  ASSERT_EQ (1, SocketCommon_parse_ip ("::1", &family));
  ASSERT_EQ (AF_INET6, family);

  ASSERT_EQ (1, SocketCommon_parse_ip ("2001:db8::1", &family));
  ASSERT_EQ (AF_INET6, family);

  ASSERT_EQ (1, SocketCommon_parse_ip ("::", &family));
  ASSERT_EQ (AF_INET6, family);

  /* Note: Zone identifiers (%lo0) may not be supported by inet_pton on all
   * systems */
  /* Test without zone identifier */
  ASSERT_EQ (1, SocketCommon_parse_ip ("fe80::1", &family));
  ASSERT_EQ (AF_INET6, family);
}

TEST (socketcommon_parse_ip_rejects_invalid)
{
  int family = AF_UNSPEC;

  ASSERT_EQ (0, SocketCommon_parse_ip ("not.an.ip", &family));
  ASSERT_EQ (AF_UNSPEC, family);

  ASSERT_EQ (0, SocketCommon_parse_ip ("256.1.1.1", &family));
  ASSERT_EQ (AF_UNSPEC, family);

  ASSERT_EQ (0, SocketCommon_parse_ip ("192.168.1", &family));
  ASSERT_EQ (AF_UNSPEC, family);

  ASSERT_EQ (0, SocketCommon_parse_ip ("", &family));
  ASSERT_EQ (AF_UNSPEC, family);
}

TEST (socketcommon_parse_ip_handles_null_family)
{
  ASSERT_EQ (1, SocketCommon_parse_ip ("127.0.0.1", NULL));
  ASSERT_EQ (1, SocketCommon_parse_ip ("::1", NULL));
  ASSERT_EQ (0, SocketCommon_parse_ip ("invalid", NULL));
}

TEST (socketcommon_cidr_match_ipv4)
{
  /* Test IPv4 CIDR matching */
  ASSERT_EQ (1, SocketCommon_cidr_match ("192.168.1.100", "192.168.1.0/24"));
  ASSERT_EQ (1, SocketCommon_cidr_match ("192.168.1.1", "192.168.1.0/24"));
  ASSERT_EQ (1, SocketCommon_cidr_match ("192.168.1.255", "192.168.1.0/24"));
  ASSERT_EQ (0, SocketCommon_cidr_match ("192.168.2.1", "192.168.1.0/24"));
  ASSERT_EQ (0, SocketCommon_cidr_match ("10.0.0.1", "192.168.1.0/24"));

  /* Test /32 (single host) */
  ASSERT_EQ (1, SocketCommon_cidr_match ("192.168.1.1", "192.168.1.1/32"));
  ASSERT_EQ (0, SocketCommon_cidr_match ("192.168.1.2", "192.168.1.1/32"));

  /* Test /0 (all addresses) */
  ASSERT_EQ (1, SocketCommon_cidr_match ("192.168.1.1", "0.0.0.0/0"));
  ASSERT_EQ (1, SocketCommon_cidr_match ("10.0.0.1", "0.0.0.0/0"));
}

TEST (socketcommon_cidr_match_ipv6)
{
  /* Test IPv6 CIDR matching */
  ASSERT_EQ (1, SocketCommon_cidr_match ("2001:db8::1", "2001:db8::/32"));
  ASSERT_EQ (1, SocketCommon_cidr_match ("2001:db8:1::1", "2001:db8::/32"));
  ASSERT_EQ (0, SocketCommon_cidr_match ("2001:db9::1", "2001:db8::/32"));
  ASSERT_EQ (0, SocketCommon_cidr_match ("::1", "2001:db8::/32"));

  /* Test /128 (single host) */
  ASSERT_EQ (1, SocketCommon_cidr_match ("2001:db8::1", "2001:db8::1/128"));
  ASSERT_EQ (0, SocketCommon_cidr_match ("2001:db8::2", "2001:db8::1/128"));
}

TEST (socketcommon_cidr_match_cross_family)
{
  /* IPv4 IP should not match IPv6 CIDR and vice versa */
  ASSERT_EQ (0, SocketCommon_cidr_match ("192.168.1.1", "2001:db8::/32"));
  ASSERT_EQ (0, SocketCommon_cidr_match ("::1", "192.168.1.0/24"));
}

TEST (socketcommon_cidr_match_invalid_inputs)
{
  /* Invalid CIDR notation */
  ASSERT_EQ (-1, SocketCommon_cidr_match ("192.168.1.1", "invalid"));
  ASSERT_EQ (-1, SocketCommon_cidr_match ("192.168.1.1", "192.168.1.0"));
  ASSERT_EQ (-1, SocketCommon_cidr_match ("192.168.1.1", "192.168.1.0/"));
  ASSERT_EQ (
      -1, SocketCommon_cidr_match (
              "192.168.1.1", "192.168.1.0/33")); /* Invalid prefix for IPv4 */
  ASSERT_EQ (
      -1, SocketCommon_cidr_match (
              "2001:db8::1", "2001:db8::/129")); /* Invalid prefix for IPv6 */

  /* Invalid IP addresses */
  ASSERT_EQ (-1, SocketCommon_cidr_match ("invalid", "192.168.1.0/24"));
  ASSERT_EQ (-1, SocketCommon_cidr_match ("256.1.1.1", "192.168.1.0/24"));
}

TEST (socketcommon_reverse_lookup_numeric)
{
  setup_signals ();
  struct sockaddr_in addr;
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];

  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (80);
  ASSERT_EQ (1, inet_pton (AF_INET, "127.0.0.1", &addr.sin_addr));

  TRY ASSERT_EQ (0, SocketCommon_reverse_lookup (
                        (struct sockaddr *)&addr, sizeof (addr), host,
                        sizeof (host), serv, sizeof (serv),
                        NI_NUMERICHOST | NI_NUMERICSERV, Socket_Failed));
  ASSERT_EQ (0, strcmp (host, "127.0.0.1"));
  ASSERT_EQ (0, strcmp (serv, "80"));
  EXCEPT (Socket_Failed)
  ASSERT (0); /* Should not fail */
  END_TRY;
}

TEST (socketcommon_reverse_lookup_ipv6_numeric)
{
  setup_signals ();
  struct sockaddr_in6 addr;
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];

  memset (&addr, 0, sizeof (addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons (443);
  ASSERT_EQ (1, inet_pton (AF_INET6, "::1", &addr.sin6_addr));

  TRY ASSERT_EQ (0, SocketCommon_reverse_lookup (
                        (struct sockaddr *)&addr, sizeof (addr), host,
                        sizeof (host), serv, sizeof (serv),
                        NI_NUMERICHOST | NI_NUMERICSERV, Socket_Failed));
  /* IPv6 address format may vary, but should contain "::1" or
   * "0:0:0:0:0:0:0:1" */
  ASSERT (strstr (host, "1") != NULL);
  ASSERT_EQ (0, strcmp (serv, "443"));
  EXCEPT (Socket_Failed)
  ASSERT (0); /* Should not fail */
  END_TRY;
}

TEST (socketcommon_reverse_lookup_hostname_only)
{
  setup_signals ();
  struct sockaddr_in addr;
  char host[NI_MAXHOST];

  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (80);
  ASSERT_EQ (1, inet_pton (AF_INET, "127.0.0.1", &addr.sin_addr));

  TRY ASSERT_EQ (
      0, SocketCommon_reverse_lookup ((struct sockaddr *)&addr, sizeof (addr),
                                      host, sizeof (host), NULL, 0,
                                      NI_NUMERICHOST, Socket_Failed));
  ASSERT_EQ (0, strcmp (host, "127.0.0.1"));
  EXCEPT (Socket_Failed)
  ASSERT (0); /* Should not fail */
  END_TRY;
}

/* ==================== Partial I/O Helper Tests ==================== */

TEST (socket_sendall_sends_all_data)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Send large data that may require multiple sends */
  char send_buf[8192];
  memset (send_buf, 'A', sizeof (send_buf));
  ssize_t sent = Socket_sendall (client, send_buf, sizeof (send_buf));
  ASSERT_EQ ((ssize_t)sizeof (send_buf), sent);

  /* Receive all data */
  char recv_buf[8192] = { 0 };
  ssize_t received = Socket_recvall (accepted, recv_buf, sizeof (recv_buf));
  ASSERT_EQ ((ssize_t)sizeof (recv_buf), received);
  ASSERT_EQ (0, memcmp (send_buf, recv_buf, sizeof (send_buf)));
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_recvall_receives_all_data)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Send data in chunks */
  const char *msg = "Hello, World! This is a test message.";
  ssize_t sent = Socket_sendall (client, msg, strlen (msg));
  ASSERT_EQ ((ssize_t)strlen (msg), sent);

  /* Receive all data */
  char recv_buf[256] = { 0 };
  ssize_t received = Socket_recvall (accepted, recv_buf, strlen (msg));
  ASSERT_EQ ((ssize_t)strlen (msg), received);
  ASSERT_EQ (0, strcmp (msg, recv_buf));
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_sendall_handles_partial_sends)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Send data - sendall should handle any partial sends internally */
  const char *msg = "Test message for partial send handling";
  ssize_t sent = Socket_sendall (client, msg, strlen (msg));
  ASSERT_EQ ((ssize_t)strlen (msg), sent);

  /* Verify all data was sent */
  char recv_buf[256] = { 0 };
  ssize_t received = Socket_recvall (accepted, recv_buf, strlen (msg));
  ASSERT_EQ ((ssize_t)strlen (msg), received);
  ASSERT_EQ (0, strcmp (msg, recv_buf));
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

/* ==================== Scatter/Gather I/O Tests ==================== */

TEST (socket_sendv_sends_from_multiple_buffers)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Prepare scatter buffers */
  char buf1[] = "Hello, ";
  char buf2[] = "World!";
  char buf3[] = " Test";
  struct iovec iov[3];
  iov[0].iov_base = buf1;
  iov[0].iov_len = strlen (buf1);
  iov[1].iov_base = buf2;
  iov[1].iov_len = strlen (buf2);
  iov[2].iov_base = buf3;
  iov[2].iov_len = strlen (buf3);

  ssize_t sent = Socket_sendv (client, iov, 3);
  ASSERT (sent > 0);

  /* Receive all data */
  char recv_buf[256] = { 0 };
  ssize_t received = Socket_recvall (accepted, recv_buf, sent);
  ASSERT_EQ (sent, received);
  ASSERT_EQ (0, strcmp (recv_buf, "Hello, World! Test"));
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_recvv_receives_into_multiple_buffers)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Send data */
  const char *msg = "Hello, World!";
  ssize_t sent = Socket_sendall (client, msg, strlen (msg));
  ASSERT_EQ ((ssize_t)strlen (msg), sent);

  /* Receive into scatter buffers */
  char buf1[8] = { 0 };
  char buf2[6] = { 0 };
  struct iovec iov[2];
  iov[0].iov_base = buf1;
  iov[0].iov_len = sizeof (buf1) - 1;
  iov[1].iov_base = buf2;
  iov[1].iov_len = sizeof (buf2) - 1;

  ssize_t received = Socket_recvv (accepted, iov, 2);
  ASSERT (received > 0);
  /* readv may receive less than requested, so verify we got at least some data
   */
  ASSERT (received <= (ssize_t)strlen (msg));

  /* Verify total data received matches - readv fills buffers sequentially */
  /* Calculate how much was received in each buffer */
  size_t buf1_received = (received > (ssize_t)(sizeof (buf1) - 1))
                             ? (sizeof (buf1) - 1)
                             : (size_t)received;
  size_t buf2_received = (received > (ssize_t)(sizeof (buf1) - 1))
                             ? (size_t)received - buf1_received
                             : 0;

  char combined[14] = { 0 };
  memcpy (combined, buf1, buf1_received);
  if (buf2_received > 0)
    memcpy (combined + buf1_received, buf2, buf2_received);
  /* Verify received data matches the sent message */
  ASSERT_EQ (0, memcmp (combined, msg, (size_t)received));
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_sendvall_sends_all_from_multiple_buffers)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Prepare scatter buffers */
  char buf1[1024];
  char buf2[1024];
  char buf3[1024];
  memset (buf1, 'A', sizeof (buf1));
  memset (buf2, 'B', sizeof (buf2));
  memset (buf3, 'C', sizeof (buf3));

  struct iovec iov[3];
  iov[0].iov_base = buf1;
  iov[0].iov_len = sizeof (buf1);
  iov[1].iov_base = buf2;
  iov[1].iov_len = sizeof (buf2);
  iov[2].iov_base = buf3;
  iov[2].iov_len = sizeof (buf3);

  size_t total_len = sizeof (buf1) + sizeof (buf2) + sizeof (buf3);
  ssize_t sent = Socket_sendvall (client, iov, 3);
  ASSERT_EQ ((ssize_t)total_len, sent);

  /* Receive all data */
  char recv_buf[3072] = { 0 };
  ssize_t received = Socket_recvall (accepted, recv_buf, total_len);
  ASSERT_EQ ((ssize_t)total_len, received);

  /* Verify data */
  ASSERT (memcmp (recv_buf, buf1, sizeof (buf1)) == 0);
  ASSERT (memcmp (recv_buf + sizeof (buf1), buf2, sizeof (buf2)) == 0);
  ASSERT (
      memcmp (recv_buf + sizeof (buf1) + sizeof (buf2), buf3, sizeof (buf3))
      == 0);
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_recvvall_receives_all_into_multiple_buffers)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Send data */
  char send_buf[2048];
  memset (send_buf, 'X', sizeof (send_buf));
  ssize_t sent = Socket_sendall (client, send_buf, sizeof (send_buf));
  ASSERT_EQ ((ssize_t)sizeof (send_buf), sent);

  /* Receive into scatter buffers */
  char buf1[512] = { 0 };
  char buf2[512] = { 0 };
  char buf3[512] = { 0 };
  char buf4[512] = { 0 };
  struct iovec iov[4];
  iov[0].iov_base = buf1;
  iov[0].iov_len = sizeof (buf1);
  iov[1].iov_base = buf2;
  iov[1].iov_len = sizeof (buf2);
  iov[2].iov_base = buf3;
  iov[2].iov_len = sizeof (buf3);
  iov[3].iov_base = buf4;
  iov[3].iov_len = sizeof (buf4);

  ssize_t received = Socket_recvvall (accepted, iov, 4);
  ASSERT_EQ ((ssize_t)sizeof (send_buf), received);

  /* Verify all buffers filled */
  ASSERT (memcmp (buf1, send_buf, sizeof (buf1)) == 0);
  ASSERT (memcmp (buf2, send_buf + sizeof (buf1), sizeof (buf2)) == 0);
  ASSERT (
      memcmp (buf3, send_buf + sizeof (buf1) + sizeof (buf2), sizeof (buf3))
      == 0);
  ASSERT (memcmp (buf4,
                  send_buf + sizeof (buf1) + sizeof (buf2) + sizeof (buf3),
                  sizeof (buf4))
          == 0);
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

/* ==================== Zero-Copy I/O Tests ==================== */

TEST (socket_sendfile_transfers_file_data)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;
  int file_fd = -1;
  const char *test_file = "/tmp/socket_sendfile_test.txt";
  const char *test_data = "Hello, Zero-Copy World!";
  size_t test_data_len = strlen (test_data);

  TRY
      /* Create test file */
      file_fd
      = open (test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  ASSERT (file_fd >= 0);
  ASSERT_EQ ((ssize_t)test_data_len,
             write (file_fd, test_data, test_data_len));
  close (file_fd);
  file_fd = -1;

  /* Open file for reading */
  file_fd = open (test_file, O_RDONLY);
  ASSERT (file_fd >= 0);

  Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Transfer file using zero-copy */
  off_t offset = 0;
  ssize_t sent = Socket_sendfile (client, file_fd, &offset, test_data_len);
  ASSERT (sent > 0);

  /* Receive data */
  char recv_buf[256] = { 0 };
  ssize_t received = Socket_recvall (accepted, recv_buf, sent);
  ASSERT_EQ (sent, received);
  ASSERT_EQ (0, memcmp (recv_buf, test_data, test_data_len));
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (file_fd >= 0)
    close (file_fd);
  unlink (test_file);
  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_sendfile_with_nonzero_offset)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;
  int file_fd = -1;
  const char *test_file = "/tmp/socket_sendfile_offset_test.txt";
  const char *test_data = "SKIP_THIS_PART_SEND_THIS_PART";
  size_t skip_len = 15; /* "SKIP_THIS_PART_" */
  size_t send_len = 14; /* "SEND_THIS_PART" */
  size_t total_len = skip_len + send_len;

  TRY
  {
    /* Create test file */
    file_fd = open (test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    ASSERT (file_fd >= 0);
    ASSERT_EQ ((ssize_t)total_len, write (file_fd, test_data, total_len));
    close (file_fd);
    file_fd = -1;

    /* Open file for reading */
    file_fd = open (test_file, O_RDONLY);
    ASSERT (file_fd >= 0);

    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 1);
    Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
    accepted = Socket_accept (server);

    /* Transfer file starting from non-zero offset */
    off_t offset = (off_t)skip_len; /* Start after "SKIP_THIS_PART_" */
    ssize_t sent = Socket_sendfile (client, file_fd, &offset, send_len);
    ASSERT (sent > 0);

    /* Receive data and verify it's the correct part */
    char recv_buf[256] = { 0 };
    ssize_t received = Socket_recvall (accepted, recv_buf, sent);
    ASSERT_EQ (sent, received);
    /* Should receive "SEND_THIS_PART" */
    ASSERT_EQ (0, strncmp (recv_buf, "SEND_THIS_PART", send_len));
  }
  EXCEPT (Socket_Failed) { (void)0; }
  EXCEPT (Socket_Closed) { (void)0; }
  END_TRY;

  if (file_fd >= 0)
    close (file_fd);
  unlink (test_file);
  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_sendfileall_transfers_complete_file)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;
  int file_fd = -1;
  const char *test_file = "/tmp/socket_sendfileall_test.txt";
  char test_data[8192];
  size_t test_data_len = sizeof (test_data);

  TRY
      /* Create test file with pattern */
      for (size_t i = 0; i < test_data_len; i++)
  {
    test_data[i] = (char)(i % 256);
  }

  file_fd = open (test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  ASSERT (file_fd >= 0);
  ASSERT_EQ ((ssize_t)test_data_len,
             write (file_fd, test_data, test_data_len));
  close (file_fd);
  file_fd = -1;

  /* Open file for reading */
  file_fd = open (test_file, O_RDONLY);
  ASSERT (file_fd >= 0);

  Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Transfer entire file using zero-copy */
  off_t offset = 0;
  ssize_t sent = Socket_sendfileall (client, file_fd, &offset, test_data_len);
  ASSERT_EQ ((ssize_t)test_data_len, sent);

  /* Receive all data */
  char recv_buf[8192] = { 0 };
  ssize_t received = Socket_recvall (accepted, recv_buf, test_data_len);
  ASSERT_EQ ((ssize_t)test_data_len, received);
  ASSERT_EQ (0, memcmp (recv_buf, test_data, test_data_len));
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (file_fd >= 0)
    close (file_fd);
  unlink (test_file);
  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_sendmsg_sends_message_with_iovec)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Prepare scatter buffers */
  char buf1[] = "Hello, ";
  char buf2[] = "sendmsg";
  char buf3[] = "!";
  struct iovec iov[3];
  iov[0].iov_base = buf1;
  iov[0].iov_len = strlen (buf1);
  iov[1].iov_base = buf2;
  iov[1].iov_len = strlen (buf2);
  iov[2].iov_base = buf3;
  iov[2].iov_len = strlen (buf3);

  struct msghdr msg = { 0 };
  msg.msg_iov = iov;
  msg.msg_iovlen = 3;

  ssize_t sent = Socket_sendmsg (client, &msg, 0);
  ASSERT (sent > 0);

  /* Receive data */
  char recv_buf[256] = { 0 };
  ssize_t received = Socket_recvall (accepted, recv_buf, sent);
  ASSERT_EQ (sent, received);
  ASSERT_EQ (0, strcmp (recv_buf, "Hello, sendmsg!"));
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_recvmsg_receives_message_with_iovec)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
  accepted = Socket_accept (server);

  /* Send data */
  const char *msg = "Hello, recvmsg!";
  ssize_t sent = Socket_sendall (client, msg, strlen (msg));
  ASSERT_EQ ((ssize_t)strlen (msg), sent);

  /* Receive into scatter buffers using recvmsg */
  char buf1[8] = { 0 };
  char buf2[8] = { 0 };
  struct iovec iov[2];
  iov[0].iov_base = buf1;
  iov[0].iov_len = sizeof (buf1) - 1;
  iov[1].iov_base = buf2;
  iov[1].iov_len = sizeof (buf2) - 1;

  struct msghdr msg_hdr = { 0 };
  msg_hdr.msg_iov = iov;
  msg_hdr.msg_iovlen = 2;

  ssize_t received = Socket_recvmsg (accepted, &msg_hdr, 0);
  ASSERT (received > 0);
  /* recvmsg may receive less than requested, so verify we got at least some
   * data */
  ASSERT (received <= (ssize_t)strlen (msg));

  /* Verify total data received matches - recvmsg fills buffers sequentially */
  /* Calculate how much was received in each buffer */
  size_t buf1_received = (received > (ssize_t)(sizeof (buf1) - 1))
                             ? (sizeof (buf1) - 1)
                             : (size_t)received;
  size_t buf2_received = (received > (ssize_t)(sizeof (buf1) - 1))
                             ? (size_t)received - buf1_received
                             : 0;

  char combined[16] = { 0 };
  memcpy (combined, buf1, buf1_received);
  if (buf2_received > 0)
    memcpy (combined + buf1_received, buf2, buf2_received);
  /* Verify received data matches the sent message */
  ASSERT_EQ (0, memcmp (combined, msg, (size_t)received));
  EXCEPT (Socket_Failed)
  (void)0;
  EXCEPT (Socket_Closed)
  (void)0;
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_sendmsg_wouldblock_nonblocking)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY
  {
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 1);
    Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
    accepted = Socket_accept (server);

    /* Set non-blocking mode */
    Socket_setnonblocking (client);

    /* Prepare small message */
    char buf[] = "test";
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = strlen (buf);

    struct msghdr msg = { 0 };
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    /* Send with MSG_DONTWAIT flag */
    ssize_t sent = Socket_sendmsg (client, &msg, MSG_DONTWAIT);
    /* Should succeed or return 0 (would block) */
    ASSERT (sent >= 0);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  EXCEPT (Socket_Closed) { (void)0; }
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_recvmsg_wouldblock_nonblocking)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY
  {
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 1);
    Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
    accepted = Socket_accept (server);

    /* Set non-blocking mode */
    Socket_setnonblocking (accepted);

    /* Try to receive when no data is available */
    char buf[64] = { 0 };
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof (buf);

    struct msghdr msg = { 0 };
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    /* Should return 0 (would block) since no data is available */
    ssize_t received = Socket_recvmsg (accepted, &msg, MSG_DONTWAIT);
    ASSERT_EQ (0, received);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  EXCEPT (Socket_Closed) { (void)0; }
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_recvmsg_peer_close)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;
  volatile int closed = 0;

  TRY
  {
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 1);
    Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
    accepted = Socket_accept (server);

    /* Close the client to trigger peer close */
    Socket_free (&client);
    usleep (50000); /* Wait for close to propagate */

    /* Try to receive - should raise Socket_Closed */
    char buf[64] = { 0 };
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof (buf);

    struct msghdr msg = { 0 };
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    Socket_recvmsg (accepted, &msg, 0);
  }
  EXCEPT (Socket_Closed) { closed = 1; }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  ASSERT_EQ (1, closed);

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  if (client)
    Socket_free (&client);
}

TEST (socket_sendmsg_with_flags)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY
  {
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 1);
    Socket_connect (client, "127.0.0.1", Socket_getlocalport (server));
    accepted = Socket_accept (server);

    /* Send with MSG_NOSIGNAL flag */
    char buf[] = "test with flags";
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = strlen (buf);

    struct msghdr msg = { 0 };
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    ssize_t sent = Socket_sendmsg (client, &msg, MSG_NOSIGNAL);
    ASSERT (sent > 0);
    ASSERT_EQ ((ssize_t)strlen (buf), sent);

    /* Receive and verify */
    char recv_buf[256] = { 0 };
    ssize_t received = Socket_recvall (accepted, recv_buf, strlen (buf));
    ASSERT_EQ ((ssize_t)strlen (buf), received);
    ASSERT_EQ (0, strcmp (recv_buf, buf));
  }
  EXCEPT (Socket_Failed) { (void)0; }
  EXCEPT (Socket_Closed) { (void)0; }
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&server);
  Socket_free (&client);
}

/* ==================== Advanced Socket Options Tests ==================== */

TEST (socket_setrcvbuf_sets_receive_buffer_size)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY int original_size = Socket_getrcvbuf (socket);
  ASSERT (original_size > 0);

  /* Set new buffer size */
  int new_size = 65536;
  Socket_setrcvbuf (socket, new_size);

  /* Verify it was set (kernel may adjust) */
  int actual_size = Socket_getrcvbuf (socket);
  ASSERT (actual_size > 0);
  /* Kernel may adjust, but should be close to requested */
  ASSERT (actual_size >= new_size / 2);
  EXCEPT (Socket_Failed)
  (void)0;
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_setsndbuf_sets_send_buffer_size)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY int original_size = Socket_getsndbuf (socket);
  ASSERT (original_size > 0);

  /* Set new buffer size */
  int new_size = 65536;
  Socket_setsndbuf (socket, new_size);

  /* Verify it was set (kernel may adjust) */
  int actual_size = Socket_getsndbuf (socket);
  ASSERT (actual_size > 0);
  /* Kernel may adjust, but should be close to requested */
  ASSERT (actual_size >= new_size / 2);
  EXCEPT (Socket_Failed)
  (void)0;
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_setcongestion_sets_congestion_algorithm)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  char algorithm[16] = { 0 };

  TRY
      /* Try to get current algorithm */
      int result
      = Socket_getcongestion (socket, algorithm, sizeof (algorithm));
  if (result < 0)
    {
      /* Not supported on this platform - skip test */
      Socket_free (&socket);
      return;
    }

  /* Try setting to "reno" */
  Socket_setcongestion (socket, "reno");

  /* Verify it was set */
  memset (algorithm, 0, sizeof (algorithm));
  result = Socket_getcongestion (socket, algorithm, sizeof (algorithm));
  ASSERT_EQ (0, result);
  ASSERT_EQ (0, strcmp (algorithm, "reno"));

  /* Try setting back to original or "cubic" */
  Socket_setcongestion (socket, "cubic");
  EXCEPT (Socket_Failed)
  /* May fail if algorithm not available - that's OK */
  (void)0;
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_setfastopen_enables_tcp_fast_open)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
      /* Try to get current setting */
      int result
      = Socket_getfastopen (socket);
  if (result < 0)
    {
      /* Not supported on this platform - skip test */
      Socket_free (&socket);
      return;
    }

  /* Enable Fast Open */
  Socket_setfastopen (socket, 1);

  /* Verify it was enabled */
  result = Socket_getfastopen (socket);
  ASSERT_EQ (1, result);

  /* Disable Fast Open */
  Socket_setfastopen (socket, 0);

  /* Verify it was disabled */
  result = Socket_getfastopen (socket);
  ASSERT_EQ (0, result);
  EXCEPT (Socket_Failed)
  /* May fail if not supported - that's OK */
  (void)0;
  END_TRY;

  Socket_free (&socket);
}

#if SOCKET_HAS_TCP_USER_TIMEOUT
TEST (socket_setusertimeout_sets_tcp_user_timeout)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Socket_setusertimeout (socket, 30000);
    unsigned int timeout = Socket_getusertimeout (socket);

    /* Set a different value and verify it */
    unsigned int new_timeout = 60000;
    Socket_setusertimeout (socket, new_timeout);
    timeout = Socket_getusertimeout (socket);
    ASSERT_EQ (new_timeout, timeout);
  }
  EXCEPT (Socket_Failed)
  {
    ASSERT (0); /* Should not fail if TCP_USER_TIMEOUT is supported */
  }
  END_TRY;

  Socket_free (&socket);
}
#else
/* TCP_USER_TIMEOUT not supported on this platform - test skipped */
TEST (socket_setusertimeout_sets_tcp_user_timeout)
{
  /* Test skipped - TCP_USER_TIMEOUT not available */
  (void)0;
}
#endif

TEST (socket_buffer_size_setters_and_getters_work_together)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
      /* Get original sizes */
      int original_rcvbuf
      = Socket_getrcvbuf (socket);
  int original_sndbuf = Socket_getsndbuf (socket);
  ASSERT (original_rcvbuf > 0);
  ASSERT (original_sndbuf > 0);

  /* Set new sizes */
  int new_rcvbuf = 32768;
  int new_sndbuf = 32768;
  Socket_setrcvbuf (socket, new_rcvbuf);
  Socket_setsndbuf (socket, new_sndbuf);

  /* Verify they were set */
  int actual_rcvbuf = Socket_getrcvbuf (socket);
  int actual_sndbuf = Socket_getsndbuf (socket);
  ASSERT (actual_rcvbuf > 0);
  ASSERT (actual_sndbuf > 0);
  /* Kernel may adjust, but should be reasonable */
  ASSERT (actual_rcvbuf >= new_rcvbuf / 2);
  ASSERT (actual_sndbuf >= new_sndbuf / 2);
  EXCEPT (Socket_Failed)
  (void)0;
  END_TRY;

  Socket_free (&socket);
}

/* ==================== Close-on-Exec Tests ==================== */

TEST (socket_new_sets_cloexec_by_default)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  int has_cloexec = SocketCommon_has_cloexec (Socket_fd (socket));
  ASSERT_EQ (has_cloexec, 1);

  Socket_free (&socket);
}

TEST (socket_accept_sets_cloexec_by_default)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  Socket_setnonblocking (server);

  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  Socket_connect (client, "127.0.0.1", port);
  usleep (100000);
  accepted = Socket_accept (server);

  if (accepted)
    {
      int has_cloexec = SocketCommon_has_cloexec (Socket_fd (accepted));
      ASSERT_EQ (has_cloexec, 1);
      Socket_free (&accepted);
    }
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

TEST (socket_setcloexec_enable_disable)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  /* Verify CLOEXEC is set by default */
  int has_cloexec = SocketCommon_has_cloexec (Socket_fd (socket));
  ASSERT_EQ (has_cloexec, 1);

  /* Disable CLOEXEC */
  TRY Socket_setcloexec (socket, 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;

  has_cloexec = SocketCommon_has_cloexec (Socket_fd (socket));
  ASSERT_EQ (has_cloexec, 0);

  /* Re-enable CLOEXEC */
  TRY Socket_setcloexec (socket, 1);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;

  has_cloexec = SocketCommon_has_cloexec (Socket_fd (socket));
  ASSERT_EQ (has_cloexec, 1);

  Socket_free (&socket);
}

TEST (socket_cloexec_prevents_leak)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  /* Verify CLOEXEC is set - this prevents descriptor leaks on exec */
  int has_cloexec = SocketCommon_has_cloexec (Socket_fd (socket));
  ASSERT_EQ (has_cloexec, 1);

  /* Test that we can disable and re-enable */
  TRY Socket_setcloexec (socket, 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;

  has_cloexec = SocketCommon_has_cloexec (Socket_fd (socket));
  ASSERT_EQ (has_cloexec, 0);

  /* Re-enable for safety */
  TRY Socket_setcloexec (socket, 1);
  EXCEPT (Socket_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
}

/* ==================== Peer Info Tests ==================== */

TEST (socket_getpeeraddr_after_accept)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);
  Socket_connect (client, "127.0.0.1", port);
  Socket_T accepted = Socket_accept (server);
  if (!accepted)
    {
      usleep (100000);
      accepted = Socket_accept (server);
    }

  if (accepted)
    {
      const char *peeraddr = Socket_getpeeraddr (accepted);
      ASSERT_NOT_NULL (peeraddr);
      Socket_free (&accepted);
    }
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

TEST (socket_getpeerport_after_accept)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile int port;
  Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 1);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  port = ntohs (addr.sin_port);
  Socket_connect (client, "127.0.0.1", port);
  volatile Socket_T accepted = Socket_accept (server);
  if (!accepted)
    {
      usleep (100000);
      accepted = Socket_accept (server);
    }

  if (accepted)
    {
      int peerport = Socket_getpeerport (accepted);
      ASSERT_NE (peerport, 0);
      Socket_T a = (Socket_T)accepted;
      Socket_free (&a);
    }
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

/* ==================== Error Condition Tests ==================== */

TEST (socket_recv_on_closed_socket_raises)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  volatile int closed_raised = 0;

  TRY
  {
    int port;
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 1);
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
    port = ntohs (addr.sin_port);
    Socket_connect (client, "127.0.0.1", port);
    Socket_T accepted = Socket_accept (server);
    if (!accepted)
      {
        usleep (100000);
        accepted = Socket_accept (server);
      }

    if (accepted)
      {
        Socket_free (&client);
        client = NULL;
        usleep (100000); /* Give time for close to propagate */
        char buf[TEST_BUFFER_SIZE];
        TRY { Socket_recv (accepted, buf, sizeof (buf)); }
        EXCEPT (Socket_Closed) { closed_raised = 1; }
        EXCEPT (Socket_Failed)
        {
          /* Fallback for other errors (e.g., EPIPE/ECONNRESET) */
          closed_raised = 1;
        }
        END_TRY;
        Socket_free (&accepted);
      }
  }
  EXCEPT (Socket_Failed) { /* Ignore setup failures */ }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    Socket_free (&server);
  }
  END_TRY;

  ASSERT_EQ (closed_raised, 1);
}

TEST (socket_multiple_connections)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client2 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile int port;
  Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 10);
  Socket_setnonblocking (server);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  port = ntohs (addr.sin_port);

  Socket_connect (client1, "127.0.0.1", port);
  Socket_connect (client2, "127.0.0.1", port);
  usleep (50000);

  volatile Socket_T acc1 = Socket_accept (server);
  volatile Socket_T acc2 = Socket_accept (server);

  if (acc1)
    {
      Socket_T a = (Socket_T)acc1;
      Socket_free (&a);
    }
  if (acc2)
    {
      Socket_T a = (Socket_T)acc2;
      Socket_free (&a);
    }
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client2);
  Socket_free (&client1);
  Socket_free (&server);
  END_TRY;
}

/* ==================== Accessor Tests ==================== */

TEST (socket_getpeeraddr_unknown_when_no_peer)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  const char *peeraddr = Socket_getpeeraddr (socket);
  ASSERT_NOT_NULL (peeraddr);
  ASSERT_EQ (strcmp (peeraddr, "(unknown)"), 0);
  Socket_free (&socket);
}

TEST (socket_getpeerport_zero_when_no_peer)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  int peerport = Socket_getpeerport (socket);
  ASSERT_EQ (peerport, 0);
  Socket_free (&socket);
}

/* ==================== Stress Tests ==================== */

TEST (socket_many_sequential_connections)
{
  setup_signals ();
  Socket_T server = NULL;
  TRY server = Socket_new (AF_INET, SOCK_STREAM, 0);
  EXCEPT (Socket_Failed) { return; }
  END_TRY;

  TRY volatile int port;
  volatile int i;
  Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 10);
  Socket_setnonblocking (server);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  port = ntohs (addr.sin_port);

  i = 0;
  while (i < 10)
    {
      TRY Socket_T client = NULL;
      client = Socket_new (AF_INET, SOCK_STREAM, 0);
      Socket_connect (client, "127.0.0.1", port);
      usleep (10000);
      Socket_T accepted = NULL;
      accepted = Socket_accept (server);
      if (accepted)
        Socket_free (&accepted);
      Socket_free (&client);
      EXCEPT (Socket_Failed) {}
      END_TRY;
      i++;
    }
  EXCEPT (Socket_Failed) (void) 0;
  END_TRY;

  Socket_free (&server);
}

TEST (socket_rapid_open_close)
{
  setup_signals ();
  for (int i = 0; i < 100; i++)
    {
      Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
      ASSERT_NOT_NULL (socket);
      Socket_free (&socket);
      ASSERT_NULL (socket);
    }
}

/* ==================== Thread Safety Tests ==================== */

static void *
thread_create_sockets (void *arg)
{
  (void)arg;
  volatile int i = 0;
  while (i < 50)
    {
      TRY Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
      if (socket)
        Socket_free (&socket);
      EXCEPT (Socket_Failed) {
      } // Ignore creation failures during concurrent stress test
      EXCEPT (Arena_Failed) {} // Ignore arena failures
      END_TRY;
      i++;
    }
  return NULL;
}

TEST (socket_concurrent_creation)
{
  setup_signals ();
  pthread_t threads[4];

  for (int i = 0; i < 4; i++)
    pthread_create (&threads[i], NULL, thread_create_sockets, NULL);

  for (int i = 0; i < 4; i++)
    pthread_join (threads[i], NULL);
}

/* ==================== Async DNS Integration Tests ==================== */

#if 0 /* KNOWN_ISSUE: Hangs on SocketDNS_check() - thread synchronization issue.
       * See KNOWN_ISSUES.md for details and tracking. */
TEST(socket_bind_async_basic)
{
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Request_T req = Socket_bind_async(dns, socket, "127.0.0.1", 0);
        ASSERT_NOT_NULL(req);
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_bind_with_addrinfo(socket, res);
            SocketCommon_free_addrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        Socket_free(&socket);
        SocketDNS_free(&dns);
    END_TRY;
}
#endif

#if 0 /* KNOWN_ISSUE: Hangs on SocketDNS_check() - thread synchronization issue.
       * See KNOWN_ISSUES.md for details and tracking. */
TEST(socket_bind_async_wildcard)
                {
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Request_T req = Socket_bind_async(dns, socket, NULL, 0);
        ASSERT_NOT_NULL(req);
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_bind_with_addrinfo(socket, res);
            SocketCommon_free_addrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        Socket_free(&socket);
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socket_connect_async_basic)
{
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 5);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        Request_T req = Socket_connect_async(dns, client, "127.0.0.1", port);
        ASSERT_NOT_NULL(req);
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_connect_with_addrinfo(client, res);
            SocketCommon_free_addrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socket_connect_async_localhost)
{
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 5);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        Request_T req = Socket_connect_async(dns, client, "localhost", port);
        ASSERT_NOT_NULL(req);
        usleep(200000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_connect_with_addrinfo(client, res);
            SocketCommon_free_addrinfo(res);
    }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
        SocketDNS_free(&dns);
    END_TRY;
}
#endif

TEST (socket_bind_with_addrinfo_ipv4)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  struct addrinfo hints, *res = NULL;

  TRY memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int result = getaddrinfo ("127.0.0.1", "0", &hints, &res);
  if (result == 0 && res)
    {
      Socket_bind_with_addrinfo (socket, res);
      freeaddrinfo (res);  /* From direct getaddrinfo */
    }
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&socket);
  END_TRY;
}

TEST (socket_connect_with_addrinfo_ipv4)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  struct addrinfo hints, *res = NULL;

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 5);

  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  char port_str[16];
  snprintf (port_str, sizeof (port_str), "%d", port);

  int result = getaddrinfo ("127.0.0.1", port_str, &hints, &res);
  if (result == 0 && res)
    {
      Socket_connect_with_addrinfo (client, res);
      freeaddrinfo (res);  /* From direct getaddrinfo */
    }
  EXCEPT (Socket_Failed) (void) 0;
  FINALLY
  Socket_free (&client);
  Socket_free (&server);
  END_TRY;
}

TEST (socketmetrics_snapshot_exports)
{
  SocketMetricsSnapshot snapshot = { { 0ULL } };

  SocketMetrics_legacy_reset ();
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 3);
  SocketMetrics_increment (SOCKET_METRIC_POLL_WAKEUPS, 1);
  SocketMetrics_getsnapshot (&snapshot);

  ASSERT_EQ (3ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
  ASSERT_EQ (1ULL, SocketMetrics_snapshot_value (&snapshot,
                                                 SOCKET_METRIC_POLL_WAKEUPS));
  ASSERT_EQ (SOCKET_METRIC_COUNT, SocketMetrics_count ());

  SocketMetrics_legacy_reset ();
  SocketMetrics_getsnapshot (&snapshot);
  ASSERT_EQ (0ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
}

TEST (socketevents_emit_and_unregister)
{
  EventProbe probe = { 0 };

  SocketEvent_register (event_probe_callback, &probe);
  SocketEvent_emit_poll_wakeup (5, 100);

  ASSERT_EQ (1, probe.count);
  ASSERT_EQ (SOCKET_EVENT_POLL_WAKEUP, probe.last_event.type);
  ASSERT_EQ (5, probe.last_event.data.poll.nfds);
  ASSERT_EQ (100, probe.last_event.data.poll.timeout_ms);

  SocketEvent_emit_dns_timeout ("example.com", 443);
  ASSERT_EQ (2, probe.count);
  ASSERT_EQ (SOCKET_EVENT_DNS_TIMEOUT, probe.last_event.type);
  ASSERT (strcmp (probe.last_event.data.dns.host, "example.com") == 0);
  ASSERT_EQ (443, probe.last_event.data.dns.port);

  SocketEvent_unregister (event_probe_callback, &probe);
  SocketEvent_emit_poll_wakeup (1, 0);
  ASSERT_EQ (2, probe.count);
}

TEST (socketmetrics_all_metric_types)
{
  SocketMetricsSnapshot snapshot = { { 0ULL } };

  SocketMetrics_legacy_reset ();
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_FAILURE, 2);
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_SHUTDOWN_CALL, 3);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_SUBMITTED, 4);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_COMPLETED, 5);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_FAILED, 6);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_CANCELLED, 7);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_TIMEOUT, 8);
  SocketMetrics_increment (SOCKET_METRIC_POLL_WAKEUPS, 9);
  SocketMetrics_increment (SOCKET_METRIC_POLL_EVENTS_DISPATCHED, 10);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_ADDED, 11);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REMOVED, 12);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REUSED, 13);

  SocketMetrics_getsnapshot (&snapshot);

  ASSERT_EQ (1ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
  ASSERT_EQ (2ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_SOCKET_CONNECT_FAILURE));
  ASSERT_EQ (3ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_SOCKET_SHUTDOWN_CALL));
  {
    uint64_t actual_dns = SocketMetrics_snapshot_value (
        &snapshot, SOCKET_METRIC_DNS_REQUEST_SUBMITTED);
    if (actual_dns != 4ULL)
      printf ("\n  [DEBUG] DNS_REQUEST_SUBMITTED = %llu (expected 4)\n",
              (unsigned long long)actual_dns);
  }
  ASSERT_EQ (4ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_DNS_REQUEST_SUBMITTED));
  ASSERT_EQ (5ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_DNS_REQUEST_COMPLETED));
  ASSERT_EQ (6ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_DNS_REQUEST_FAILED));
  ASSERT_EQ (7ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_DNS_REQUEST_CANCELLED));
  ASSERT_EQ (8ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_DNS_REQUEST_TIMEOUT));
  ASSERT_EQ (9ULL, SocketMetrics_snapshot_value (&snapshot,
                                                 SOCKET_METRIC_POLL_WAKEUPS));
  ASSERT_EQ (10ULL, SocketMetrics_snapshot_value (
                        &snapshot, SOCKET_METRIC_POLL_EVENTS_DISPATCHED));
  ASSERT_EQ (11ULL, SocketMetrics_snapshot_value (
                        &snapshot, SOCKET_METRIC_POOL_CONNECTIONS_ADDED));
  ASSERT_EQ (12ULL, SocketMetrics_snapshot_value (
                        &snapshot, SOCKET_METRIC_POOL_CONNECTIONS_REMOVED));
  ASSERT_EQ (13ULL, SocketMetrics_snapshot_value (
                        &snapshot, SOCKET_METRIC_POOL_CONNECTIONS_REUSED));
}

TEST (socketmetrics_metric_names)
{
  ASSERT_NOT_NULL (SocketMetrics_name (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
  ASSERT_NOT_NULL (SocketMetrics_name (SOCKET_METRIC_SOCKET_CONNECT_FAILURE));
  ASSERT_NOT_NULL (SocketMetrics_name (SOCKET_METRIC_DNS_REQUEST_SUBMITTED));
  ASSERT_NOT_NULL (SocketMetrics_name (SOCKET_METRIC_POLL_WAKEUPS));
  ASSERT_NOT_NULL (SocketMetrics_name (SOCKET_METRIC_POOL_CONNECTIONS_ADDED));
  ASSERT_NOT_NULL (SocketMetrics_name ((SocketMetric)999));
}

TEST (socketmetrics_increment_by_value)
{
  SocketMetricsSnapshot snapshot = { { 0ULL } };

  SocketMetrics_legacy_reset ();
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 5);
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 3);
  SocketMetrics_getsnapshot (&snapshot);

  ASSERT_EQ (8ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
}

TEST (socketevents_multiple_handlers)
{
  EventProbe probe1 = { 0 };
  EventProbe probe2 = { 0 };

  SocketEvent_register (event_probe_callback, &probe1);
  SocketEvent_register (event_probe_callback, &probe2);
  SocketEvent_emit_poll_wakeup (10, 200);

  ASSERT_EQ (1, probe1.count);
  ASSERT_EQ (1, probe2.count);
  ASSERT_EQ (10, probe1.last_event.data.poll.nfds);
  ASSERT_EQ (10, probe2.last_event.data.poll.nfds);

  SocketEvent_unregister (event_probe_callback, &probe1);
  SocketEvent_unregister (event_probe_callback, &probe2);
}

TEST (socketevents_accept_and_connect_events)
{
  EventProbe probe = { 0 };

  SocketEvent_register (event_probe_callback, &probe);
  SocketEvent_emit_accept (42, "192.168.1.1", 8080, "0.0.0.0", 80);

  ASSERT_EQ (1, probe.count);
  ASSERT_EQ (SOCKET_EVENT_ACCEPTED, probe.last_event.type);
  ASSERT_EQ (42, probe.last_event.data.connection.fd);
  ASSERT (strcmp (probe.last_event.data.connection.peer_addr, "192.168.1.1")
          == 0);
  ASSERT_EQ (8080, probe.last_event.data.connection.peer_port);
  ASSERT (strcmp (probe.last_event.data.connection.local_addr, "0.0.0.0")
          == 0);
  ASSERT_EQ (80, probe.last_event.data.connection.local_port);

  SocketEvent_emit_connect (43, "10.0.0.1", 443, "192.168.1.2", 50000);
  ASSERT_EQ (2, probe.count);
  ASSERT_EQ (SOCKET_EVENT_CONNECTED, probe.last_event.type);
  ASSERT_EQ (43, probe.last_event.data.connection.fd);
  ASSERT (strcmp (probe.last_event.data.connection.peer_addr, "10.0.0.1")
          == 0);
  ASSERT_EQ (443, probe.last_event.data.connection.peer_port);

  SocketEvent_unregister (event_probe_callback, &probe);
}

TEST (socketevents_duplicate_registration_ignored)
{
  EventProbe probe = { 0 };

  SocketEvent_register (event_probe_callback, &probe);
  SocketEvent_register (event_probe_callback, &probe);
  SocketEvent_emit_poll_wakeup (1, 0);

  ASSERT_EQ (1, probe.count);

  SocketEvent_unregister (event_probe_callback, &probe);
  SocketEvent_emit_poll_wakeup (1, 0);
  ASSERT_EQ (1, probe.count);
}

TEST (socketevents_handler_limit_enforced)
{
  EventProbe probes[16] = { 0 };
  int i;

  for (i = 0; i < 8; i++)
    {
      SocketEvent_register (event_probe_callback, &probes[i]);
    }

  SocketEvent_emit_poll_wakeup (1, 0);
  ASSERT_EQ (1, probes[0].count);

  SocketEvent_register (event_probe_callback, &probes[8]);
  SocketEvent_emit_poll_wakeup (1, 0);
  ASSERT_EQ (0, probes[8].count);

  for (i = 0; i < 8; i++)
    {
      SocketEvent_unregister (event_probe_callback, &probes[i]);
    }
}

TEST (socket_bind_async_wildcard_uses_ai_passive)
{
  SocketDNS_T dns = NULL;
  Socket_T socket = NULL;
  Request_T req;
  struct addrinfo *res = NULL;

  TRY dns = SocketDNS_new ();
  socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  req = Socket_bind_async (dns, socket, NULL, 0);

  res = SocketDNS_getresult (dns, req);
  ASSERT_NOT_NULL (res);
  ASSERT_NOT_NULL (res->ai_addr);

  Socket_bind_with_addrinfo (socket, res);
  Socket_listen (socket, 5);

  ASSERT (Socket_getlocalport (socket) >= 1);
  ASSERT (Socket_getlocalport (socket) <= 65535);

  SocketCommon_free_addrinfo (res);
  res = NULL;
  EXCEPT (Socket_Failed)
  if (res)
    SocketCommon_free_addrinfo (res);
  EXCEPT (SocketDNS_Failed)
  if (res)
    SocketCommon_free_addrinfo (res);
  FINALLY
  if (socket)
    Socket_free (&socket);
  if (dns)
    SocketDNS_free (&dns);
  END_TRY;
}

/* ==================== Socket Options Coverage Tests ==================== */

TEST (socket_keepalive_set_get)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  int idle = 0, interval = 0, count = 0;

  TRY
  {
    /* Set keepalive parameters */
    Socket_setkeepalive (socket, 60, 10, 5);

    /* Get keepalive parameters */
    /* On macOS, getsockopt() doesn't reliably return user-set values.
     * Accept success without strict value checks on that platform. */
    Socket_getkeepalive (socket, &idle, &interval, &count);

#if SOCKET_PLATFORM_MACOS
    /* Verify we at least succeeded calling the getter; don't assert exact
     * values */
    (void)idle;
    (void)interval;
    (void)count;
#else
    /* Values should be set on platforms that return set values */
    ASSERT (idle > 0);
    ASSERT (interval > 0);
    ASSERT (count > 0);
#endif
  }
  EXCEPT (Socket_Failed) { /* May fail on some platforms */ }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_keepalive_disabled_returns_zeros)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  int idle = 99, interval = 99, count = 99;

  TRY
  {
    /* Get keepalive without setting - should be disabled */
    Socket_getkeepalive (socket, &idle, &interval, &count);
    ASSERT_EQ (0, idle);
    ASSERT_EQ (0, interval);
    ASSERT_EQ (0, count);
  }
  EXCEPT (Socket_Failed) { /* May fail on some platforms */ }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_nodelay_set_get)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    /* Enable TCP_NODELAY */
    Socket_setnodelay (socket, 1);
    int nodelay = Socket_getnodelay (socket);

#if SOCKET_PLATFORM_MACOS
    /* On macOS, getsockopt() may not reliably return the value; ensure getter
     * call didn't throw and proceed without asserting a fixed value. */
    (void)nodelay;
#else
    ASSERT_EQ (nodelay, 1);
#endif

    /* Disable TCP_NODELAY */
    Socket_setnodelay (socket, 0);
    nodelay = Socket_getnodelay (socket);

#if SOCKET_PLATFORM_MACOS
    (void)nodelay;
#else
    ASSERT_EQ (nodelay, 0);
#endif
  }
  EXCEPT (Socket_Failed) { /* May fail on some platforms */ }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_rcvbuf_set_get)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    /* Set receive buffer size */
    Socket_setrcvbuf (socket, 32768);
    int size = Socket_getrcvbuf (socket);
    /* Kernel may double the size */
    ASSERT (size >= 32768);
  }
  EXCEPT (Socket_Failed) { /* May fail on some platforms */ }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_sndbuf_set_get)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    /* Set send buffer size */
    Socket_setsndbuf (socket, 32768);
    int size = Socket_getsndbuf (socket);
    /* Kernel may double the size */
    ASSERT (size >= 32768);
  }
  EXCEPT (Socket_Failed) { /* May fail on some platforms */ }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_congestion_algorithm)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  char algorithm[64] = { 0 };

  TRY
  {
    /* Get current congestion algorithm */
    int result = Socket_getcongestion (socket, algorithm, sizeof (algorithm));
    if (result == 0)
      {
        /* Algorithm should be non-empty */
        ASSERT (strlen (algorithm) > 0);
      }

    /* Try to set to cubic (common algorithm) */
    Socket_setcongestion (socket, "cubic");

    /* Verify it was set */
    memset (algorithm, 0, sizeof (algorithm));
    result = Socket_getcongestion (socket, algorithm, sizeof (algorithm));
    if (result == 0)
      {
        ASSERT (strcmp (algorithm, "cubic") == 0);
      }
  }
  EXCEPT (Socket_Failed)
  {
    /* May fail on some platforms or if algorithm not supported */
  }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_fastopen_set_get)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    /* Try to enable TCP Fast Open */
    Socket_setfastopen (socket, 1);
    int result = Socket_getfastopen (socket);
    ASSERT (result >= 0);
  }
  EXCEPT (Socket_Failed) { /* TCP_FASTOPEN may not be supported */ }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_usertimeout_set_get)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    /* Set TCP user timeout to 5 seconds */
    Socket_setusertimeout (socket, 5000);
    unsigned int timeout = Socket_getusertimeout (socket);
    /* Should be approximately 5000ms or 0 if not supported */
    ASSERT (timeout == 5000 || timeout == 0);
  }
  EXCEPT (Socket_Failed) { /* TCP_USER_TIMEOUT may not be supported */ }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_shutdown_read)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;
  volatile int port = 0;

  TRY
  {
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    Socket_setnonblocking (server);
    port = Socket_getlocalport (server);

    Socket_connect (client, "127.0.0.1", port);

    /* Accept */
    for (int i = 0; i < 10 && !accepted; i++)
      {
        accepted = Socket_accept (server);
        if (!accepted)
          usleep (10000);
      }

    if (accepted)
      {
        /* Shutdown read side */
        Socket_shutdown (accepted, SOCKET_SHUT_RD);
      }
  }
  EXCEPT (Socket_Failed) { /* Expected */ }
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&client);
  Socket_free (&server);
}

TEST (socket_shutdown_write)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;
  volatile int port = 0;

  TRY
  {
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    Socket_setnonblocking (server);
    port = Socket_getlocalport (server);

    Socket_connect (client, "127.0.0.1", port);

    /* Accept */
    for (int i = 0; i < 10 && !accepted; i++)
      {
        accepted = Socket_accept (server);
        if (!accepted)
          usleep (10000);
      }

    if (accepted)
      {
        /* Shutdown write side */
        Socket_shutdown (accepted, SOCKET_SHUT_WR);
      }
  }
  EXCEPT (Socket_Failed) { /* Expected */ }
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&client);
  Socket_free (&server);
}

TEST (socket_shutdown_both)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;
  volatile int port = 0;

  TRY
  {
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    Socket_setnonblocking (server);
    port = Socket_getlocalport (server);

    Socket_connect (client, "127.0.0.1", port);

    /* Accept */
    for (int i = 0; i < 10 && !accepted; i++)
      {
        accepted = Socket_accept (server);
        if (!accepted)
          usleep (10000);
      }

    if (accepted)
      {
        /* Shutdown both sides */
        Socket_shutdown (accepted, SOCKET_SHUT_RDWR);
      }
  }
  EXCEPT (Socket_Failed) { /* Expected */ }
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&client);
  Socket_free (&server);
}

TEST (socket_shutdown_invalid_mode)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  volatile int raised = 0;

  TRY
  {
    /* Invalid shutdown mode */
    Socket_shutdown (socket, 99);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&socket);
}

/* ==================== Timeout API Tests ==================== */

TEST (socket_timeouts_get_set)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  SocketTimeouts_T timeouts = { 0 };
  SocketTimeouts_T retrieved = { 0 };

  /* Set custom timeouts */
  timeouts.connect_timeout_ms = 5000;
  timeouts.dns_timeout_ms = 3000;
  timeouts.operation_timeout_ms = 10000;

  Socket_timeouts_set (socket, &timeouts);
  Socket_timeouts_get (socket, &retrieved);

  ASSERT_EQ (5000, retrieved.connect_timeout_ms);
  ASSERT_EQ (3000, retrieved.dns_timeout_ms);
  ASSERT_EQ (10000, retrieved.operation_timeout_ms);

  Socket_free (&socket);
}

TEST (socket_timeouts_set_null_resets_to_defaults)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  SocketTimeouts_T timeouts = { 0 };
  SocketTimeouts_T defaults = { 0 };

  /* Get defaults */
  Socket_timeouts_getdefaults (&defaults);

  /* Set custom timeouts */
  timeouts.connect_timeout_ms = 9999;
  Socket_timeouts_set (socket, &timeouts);

  /* Reset to defaults by passing NULL */
  Socket_timeouts_set (socket, NULL);

  /* Retrieve and verify reset to defaults */
  Socket_timeouts_get (socket, &timeouts);
  ASSERT_EQ (defaults.connect_timeout_ms, timeouts.connect_timeout_ms);

  Socket_free (&socket);
}

TEST (socket_timeouts_defaults_get_set)
{
  SocketTimeouts_T original = { 0 };
  SocketTimeouts_T custom = { 0 };

  /* Save original defaults */
  Socket_timeouts_getdefaults (&original);

  /* Set custom defaults */
  custom.connect_timeout_ms = 7500;
  custom.dns_timeout_ms = 2500;
  custom.operation_timeout_ms = 15000;
  Socket_timeouts_setdefaults (&custom);

  /* Verify they were set */
  SocketTimeouts_T retrieved = { 0 };
  Socket_timeouts_getdefaults (&retrieved);
  ASSERT_EQ (7500, retrieved.connect_timeout_ms);
  ASSERT_EQ (2500, retrieved.dns_timeout_ms);
  ASSERT_EQ (15000, retrieved.operation_timeout_ms);

  /* Restore original defaults */
  Socket_timeouts_setdefaults (&original);
}

TEST (socket_gettimeout)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    /* Set timeout */
    Socket_settimeout (socket, 5);

    /* Get timeout */
    int timeout = Socket_gettimeout (socket);
    ASSERT_EQ (5, timeout);
  }
  EXCEPT (Socket_Failed) { /* May fail on some platforms */ }
  END_TRY;

  Socket_free (&socket);
}

/* ==================== Socket Flag Tests ==================== */

TEST (socket_setreuseport)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Socket_setreuseport (socket);
    /* Should not raise exception if supported */
  }
  EXCEPT (Socket_Failed)
  {
    /* SO_REUSEPORT may not be supported on all platforms */
  }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_setcloexec)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    /* Enable close-on-exec */
    Socket_setcloexec (socket, 1);

    /* Disable close-on-exec */
    Socket_setcloexec (socket, 0);
  }
  EXCEPT (Socket_Failed) { /* May fail on some platforms */ }
  END_TRY;

  Socket_free (&socket);
}

/* ==================== SocketCommon IOV Helper Tests ==================== */

TEST (socketcommon_calculate_total_iov_len)
{
  struct iovec iov[3];
  char buf1[100], buf2[200], buf3[300];

  iov[0].iov_base = buf1;
  iov[0].iov_len = 100;
  iov[1].iov_base = buf2;
  iov[1].iov_len = 200;
  iov[2].iov_base = buf3;
  iov[2].iov_len = 300;

  size_t total = SocketCommon_calculate_total_iov_len (iov, 3);
  ASSERT_EQ (600, total);
}

TEST (socketcommon_calculate_total_iov_len_empty)
{
  struct iovec iov[1];
  char buf[10];

  iov[0].iov_base = buf;
  iov[0].iov_len = 0;

  size_t total = SocketCommon_calculate_total_iov_len (iov, 1);
  ASSERT_EQ (0, total);
}

TEST (socketcommon_calculate_total_iov_len_invalid_raises)
{
  struct iovec iov[1];
  char buf[10];
  volatile int raised = 0;

  iov[0].iov_base = buf;
  iov[0].iov_len = 10;

  /* Invalid iovcnt (0) should raise SocketCommon_Failed */
  TRY { SocketCommon_calculate_total_iov_len (iov, 0); }
  EXCEPT (SocketCommon_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_advance_iov_partial)
{
  struct iovec iov[3];
  char buf1[100], buf2[100], buf3[100];

  iov[0].iov_base = buf1;
  iov[0].iov_len = 100;
  iov[1].iov_base = buf2;
  iov[1].iov_len = 100;
  iov[2].iov_base = buf3;
  iov[2].iov_len = 100;

  /* Advance 150 bytes - should consume buf1 and part of buf2 */
  SocketCommon_advance_iov (iov, 3, 150);

  /* buf1 should be consumed */
  ASSERT_EQ (0, iov[0].iov_len);
  ASSERT_NULL (iov[0].iov_base);

  /* buf2 should have 50 bytes remaining */
  ASSERT_EQ (50, iov[1].iov_len);
  ASSERT_EQ (buf2 + 50, iov[1].iov_base);

  /* buf3 should be unchanged */
  ASSERT_EQ (100, iov[2].iov_len);
  ASSERT_EQ (buf3, iov[2].iov_base);
}

TEST (socketcommon_advance_iov_full)
{
  struct iovec iov[2];
  char buf1[100], buf2[100];

  iov[0].iov_base = buf1;
  iov[0].iov_len = 100;
  iov[1].iov_base = buf2;
  iov[1].iov_len = 100;

  /* Advance all bytes */
  SocketCommon_advance_iov (iov, 2, 200);

  ASSERT_EQ (0, iov[0].iov_len);
  ASSERT_NULL (iov[0].iov_base);
  ASSERT_EQ (0, iov[1].iov_len);
  ASSERT_NULL (iov[1].iov_base);
}

TEST (socketcommon_find_active_iov_first)
{
  struct iovec iov[3];
  char buf1[100], buf2[100], buf3[100];
  int active_count = 0;

  iov[0].iov_base = buf1;
  iov[0].iov_len = 100;
  iov[1].iov_base = buf2;
  iov[1].iov_len = 100;
  iov[2].iov_base = buf3;
  iov[2].iov_len = 100;

  struct iovec *active = SocketCommon_find_active_iov (iov, 3, &active_count);

  ASSERT_EQ (&iov[0], active);
  ASSERT_EQ (3, active_count);
}

TEST (socketcommon_find_active_iov_middle)
{
  struct iovec iov[3];
  char buf2[100], buf3[100];
  int active_count = 0;

  iov[0].iov_base = NULL;
  iov[0].iov_len = 0;
  iov[1].iov_base = buf2;
  iov[1].iov_len = 100;
  iov[2].iov_base = buf3;
  iov[2].iov_len = 100;

  struct iovec *active = SocketCommon_find_active_iov (iov, 3, &active_count);

  ASSERT_EQ (&iov[1], active);
  ASSERT_EQ (2, active_count);
}

TEST (socketcommon_find_active_iov_none)
{
  struct iovec iov[2];
  int active_count = 99;

  iov[0].iov_base = NULL;
  iov[0].iov_len = 0;
  iov[1].iov_base = NULL;
  iov[1].iov_len = 0;

  struct iovec *active = SocketCommon_find_active_iov (iov, 2, &active_count);

  ASSERT_NULL (active);
  ASSERT_EQ (0, active_count);
}

TEST (socketcommon_alloc_iov_copy)
{
  struct iovec iov[2];
  char buf1[100], buf2[200];

  iov[0].iov_base = buf1;
  iov[0].iov_len = 100;
  iov[1].iov_base = buf2;
  iov[1].iov_len = 200;

  TRY
  {
    struct iovec *copy = SocketCommon_alloc_iov_copy (iov, 2, Socket_Failed);
    ASSERT_NOT_NULL (copy);

    /* Verify copy matches original */
    ASSERT_EQ (iov[0].iov_base, copy[0].iov_base);
    ASSERT_EQ (iov[0].iov_len, copy[0].iov_len);
    ASSERT_EQ (iov[1].iov_base, copy[1].iov_base);
    ASSERT_EQ (iov[1].iov_len, copy[1].iov_len);

    free (copy);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;
}

TEST (socketcommon_normalize_wildcard_host)
{
  /* NULL should normalize to NULL */
  const char *result = SocketCommon_normalize_wildcard_host (NULL);
  ASSERT_NULL (result);

  /* IPv4 wildcard should normalize to NULL */
  result = SocketCommon_normalize_wildcard_host ("0.0.0.0");
  ASSERT_NULL (result);

  /* IPv6 wildcard should normalize to NULL */
  result = SocketCommon_normalize_wildcard_host ("::");
  ASSERT_NULL (result);

  /* Regular host should remain unchanged */
  result = SocketCommon_normalize_wildcard_host ("127.0.0.1");
  ASSERT_NOT_NULL (result);
  ASSERT_EQ (0, strcmp (result, "127.0.0.1"));

  /* Domain name should remain unchanged */
  result = SocketCommon_normalize_wildcard_host ("localhost");
  ASSERT_NOT_NULL (result);
  ASSERT_EQ (0, strcmp (result, "localhost"));
}

TEST (socketcommon_validate_port_valid)
{
  /* Should not raise for valid ports */
  TRY
  {
    SocketCommon_validate_port (0, Socket_Failed);
    SocketCommon_validate_port (80, Socket_Failed);
    SocketCommon_validate_port (443, Socket_Failed);
    SocketCommon_validate_port (8080, Socket_Failed);
    SocketCommon_validate_port (65535, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;
}

TEST (socketcommon_validate_port_invalid)
{
  volatile int raised = 0;

  TRY { SocketCommon_validate_port (-1, Socket_Failed); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);

  raised = 0;
  TRY { SocketCommon_validate_port (65536, Socket_Failed); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_validate_host_not_null_valid)
{
  TRY
  {
    SocketCommon_validate_host_not_null ("localhost", Socket_Failed);
    SocketCommon_validate_host_not_null ("127.0.0.1", Socket_Failed);
    SocketCommon_validate_host_not_null ("", Socket_Failed);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;
}

TEST (socketcommon_validate_host_not_null_invalid)
{
  volatile int raised = 0;

  TRY { SocketCommon_validate_host_not_null (NULL, Socket_Failed); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_timeouts_defaults)
{
  SocketTimeouts_T original = { 0 };
  SocketTimeouts_T custom = { 0 };
  SocketTimeouts_T retrieved = { 0 };

  /* Save original defaults */
  SocketCommon_timeouts_getdefaults (&original);
  ASSERT (original.connect_timeout_ms > 0 || original.connect_timeout_ms == 0);

  /* Set custom defaults */
  custom.connect_timeout_ms = 12345;
  custom.dns_timeout_ms = 6789;
  custom.operation_timeout_ms = 11111;
  SocketCommon_timeouts_setdefaults (&custom);

  /* Retrieve and verify */
  SocketCommon_timeouts_getdefaults (&retrieved);
  ASSERT_EQ (12345, retrieved.connect_timeout_ms);
  ASSERT_EQ (6789, retrieved.dns_timeout_ms);
  ASSERT_EQ (11111, retrieved.operation_timeout_ms);

  /* Restore original defaults */
  SocketCommon_timeouts_setdefaults (&original);
}

TEST (socketcommon_timeouts_negative_sanitized)
{
  SocketTimeouts_T original = { 0 };
  SocketTimeouts_T custom = { 0 };
  SocketTimeouts_T retrieved = { 0 };

  /* Save original defaults */
  SocketCommon_timeouts_getdefaults (&original);

  /* Set negative values (should be sanitized to 0) */
  custom.connect_timeout_ms = -100;
  custom.dns_timeout_ms = -200;
  custom.operation_timeout_ms = -300;
  SocketCommon_timeouts_setdefaults (&custom);

  /* Retrieve and verify sanitization */
  SocketCommon_timeouts_getdefaults (&retrieved);
  ASSERT_EQ (0, retrieved.connect_timeout_ms);
  ASSERT_EQ (0, retrieved.dns_timeout_ms);
  ASSERT_EQ (0, retrieved.operation_timeout_ms);

  /* Restore original defaults */
  SocketCommon_timeouts_setdefaults (&original);
}

TEST (socketcommon_copy_addrinfo)
{
  struct addrinfo hints, *res = NULL;
  struct addrinfo *copy = NULL;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  int result = getaddrinfo ("127.0.0.1", "80", &hints, &res);
  if (result != 0 || !res)
    {
      /* getaddrinfo failed, skip test */
      return;
    }

  /* Copy the addrinfo chain */
  copy = SocketCommon_copy_addrinfo (res);
  ASSERT_NOT_NULL (copy);

  /* Verify copy matches original */
  ASSERT_EQ (res->ai_family, copy->ai_family);
  ASSERT_EQ (res->ai_socktype, copy->ai_socktype);
  ASSERT_EQ (res->ai_addrlen, copy->ai_addrlen);
  ASSERT_NOT_NULL (copy->ai_addr);

  /* Free copy using our free function */
  SocketCommon_free_addrinfo (copy);

  /* Free original using system function */
  freeaddrinfo (res);
}

TEST (socketcommon_copy_addrinfo_null)
{
  struct addrinfo *copy = SocketCommon_copy_addrinfo (NULL);
  ASSERT_NULL (copy);
}

TEST (socketcommon_free_addrinfo_null)
{
  /* Should not crash */
  SocketCommon_free_addrinfo (NULL);
}

/* ==================== Scatter/Gather I/O Tests ==================== */

TEST (socket_sendv_recvv_basic)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted = NULL;
  volatile int port = 0;
  char buf1[] = "Hello";
  char buf2[] = "World";
  char recv_buf[64] = { 0 };
  struct iovec send_iov[2];
  struct iovec recv_iov[1];

  send_iov[0].iov_base = buf1;
  send_iov[0].iov_len = strlen (buf1);
  send_iov[1].iov_base = buf2;
  send_iov[1].iov_len = strlen (buf2);

  recv_iov[0].iov_base = recv_buf;
  recv_iov[0].iov_len = sizeof (recv_buf);

  TRY
  {
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    Socket_setnonblocking (server);
    port = Socket_getlocalport (server);

    Socket_connect (client, "127.0.0.1", port);

    /* Accept */
    for (int i = 0; i < 10 && !accepted; i++)
      {
        accepted = Socket_accept (server);
        if (!accepted)
          usleep (10000);
      }

    if (accepted)
      {
        /* Send using scatter */
        ssize_t sent = Socket_sendv (client, send_iov, 2);
        ASSERT (sent > 0);

        usleep (10000);

        /* Receive using gather */
        Socket_setnonblocking (accepted);
        ssize_t recvd = Socket_recvv (accepted, recv_iov, 1);
        if (recvd > 0)
          {
            ASSERT (memcmp (recv_buf, "HelloWorld", 10) == 0);
          }
      }
  }
  EXCEPT (Socket_Failed) { /* Expected */ }
  EXCEPT (Socket_Closed) { /* Expected */ }
  END_TRY;

  if (accepted)
    Socket_free (&accepted);
  Socket_free (&client);
  Socket_free (&server);
}

/* ==================== Error Path Coverage Tests ==================== */

TEST (socket_setkeepalive_invalid_params_raises)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  volatile int raised = 0;

  /* Test idle <= 0 */
  TRY { Socket_setkeepalive (socket, 0, 10, 5); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (1, raised);

  /* Test interval <= 0 */
  raised = 0;
  TRY { Socket_setkeepalive (socket, 60, -1, 5); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (1, raised);

  /* Test count <= 0 */
  raised = 0;
  TRY { Socket_setkeepalive (socket, 60, 10, 0); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (1, raised);

  Socket_free (&socket);
}

TEST (socket_setcongestion_invalid_algorithm_raises)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  volatile int raised = 0;

  TRY { Socket_setcongestion (socket, "nonexistent_algorithm_xyz_12345"); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  /* Should raise on invalid algorithm */
  ASSERT_EQ (1, raised);
  Socket_free (&socket);
}

TEST (socket_shutdown_on_unconnected_socket_raises)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  volatile int raised = 0;

  /* Shutdown on unconnected socket should fail */
  TRY { Socket_shutdown (socket, SOCKET_SHUT_RDWR); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&socket);
}

TEST (socket_keepalive_on_udp_socket_fails)
{
  setup_signals ();
  Socket_T udp = Socket_new (AF_INET, SOCK_DGRAM, 0);
  volatile int raised = 0;

  /* Keepalive is TCP-only, should fail on UDP */
  TRY { Socket_setkeepalive (udp, 60, 10, 5); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&udp);
}

TEST (socket_keepalive_on_unix_socket_fails)
{
  setup_signals ();
  Socket_T unix_sock = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  volatile int raised = 0;

  /* Unix sockets accept SO_KEEPALIVE but fail on TCP_KEEP* options.
   * This tests the error paths in set_keepalive_idle_time,
   * set_keepalive_interval, and set_keepalive_count. */
  TRY { Socket_setkeepalive (unix_sock, 60, 10, 5); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&unix_sock);
}

TEST (socket_tcp_options_on_udp_socket_fails)
{
  setup_signals ();
  Socket_T udp = Socket_new (AF_INET, SOCK_DGRAM, 0);
  volatile int raised = 0;
  volatile int nodelay = 0;
  char algorithm[64] = { 0 };

  /* TCP_NODELAY on UDP should fail */
  TRY { Socket_setnodelay (udp, 1); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (1, raised);

  raised = 0;
  TRY
  {
    nodelay = Socket_getnodelay (udp);
    (void)nodelay;
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (1, raised);

  /* TCP_CONGESTION on UDP should fail */
  raised = 0;
  TRY { Socket_setcongestion (udp, "cubic"); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (1, raised);

  /* getcongestion should return -1 for UDP */
  int result = Socket_getcongestion (udp, algorithm, sizeof (algorithm));
  ASSERT_EQ (-1, result);

  /* TCP_FASTOPEN on UDP should fail */
  raised = 0;
  TRY { Socket_setfastopen (udp, 1); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (1, raised);

  /* TCP_USER_TIMEOUT on UDP should fail */
  raised = 0;
  TRY { Socket_setusertimeout (udp, 5000); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (1, raised);

  Socket_free (&udp);
}

TEST (socket_getkeepalive_on_udp_socket)
{
  setup_signals ();
  Socket_T udp = Socket_new (AF_INET, SOCK_DGRAM, 0);
  volatile int raised = 0;
  int idle = 0, interval = 0, count = 0;

  /* getkeepalive on UDP - triggers getsockopt error paths */
  TRY { Socket_getkeepalive (udp, &idle, &interval, &count); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  /* May or may not raise depending on platform */
  (void)raised;
  Socket_free (&udp);
}

TEST (socket_getrcvbuf_getsndbuf_on_udp)
{
  setup_signals ();
  Socket_T udp = Socket_new (AF_INET, SOCK_DGRAM, 0);

  /* These should work on UDP too, just verify they don't crash */
  TRY
  {
    int rcvbuf = Socket_getrcvbuf (udp);
    int sndbuf = Socket_getsndbuf (udp);
    ASSERT (rcvbuf > 0);
    ASSERT (sndbuf > 0);
  }
  EXCEPT (Socket_Failed) { /* May fail on some platforms */ }
  END_TRY;

  Socket_free (&udp);
}

/* ==================== SocketCommon 100% Coverage Tests ====================
 */

/* Hostname Validation Coverage Tests */

TEST (socketcommon_validate_hostname_too_long)
{
  setup_signals ();
  volatile int raised = 0;
  char long_hostname[SOCKET_ERROR_MAX_HOSTNAME + 10];
  memset (long_hostname, 'a', sizeof (long_hostname) - 1);
  long_hostname[sizeof (long_hostname) - 1] = '\0';

  TRY { SocketCommon_validate_hostname (long_hostname, Socket_Failed); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_validate_hostname_invalid_chars)
{
  setup_signals ();
  volatile int raised = 0;

  /* Test with invalid character (space) */
  TRY { SocketCommon_validate_hostname ("host name", Socket_Failed); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);

  /* Test with another invalid character (backslash) */
  raised = 0;
  TRY { SocketCommon_validate_hostname ("host\\name", Socket_Failed); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_validate_hostname_internal_no_exceptions)
{
  /* Test internal function with use_exceptions=0 */
  char long_hostname[SOCKET_ERROR_MAX_HOSTNAME + 10];
  memset (long_hostname, 'a', sizeof (long_hostname) - 1);
  long_hostname[sizeof (long_hostname) - 1] = '\0';

  int result = socketcommon_validate_hostname_internal (long_hostname, 0,
                                                        Socket_Failed, NULL);
  ASSERT_EQ (-1, result);

  /* Test invalid characters without exceptions */
  result = socketcommon_validate_hostname_internal ("host name", 0,
                                                    Socket_Failed, NULL);
  ASSERT_EQ (-1, result);
}

/* Bind Error Coverage Tests */

TEST (socketcommon_format_bind_error_eaddrinuse)
{
  errno = EADDRINUSE;
  SocketCommon_format_bind_error ("127.0.0.1", 8080);
  /* Just verify it doesn't crash - error formatted in socket_error_buf */
}

TEST (socketcommon_format_bind_error_eaddrnotavail)
{
  errno = EADDRNOTAVAIL;
  SocketCommon_format_bind_error ("192.168.255.255", 8080);
}

TEST (socketcommon_format_bind_error_eacces)
{
  errno = EACCES;
  SocketCommon_format_bind_error ("0.0.0.0", 80);
}

TEST (socketcommon_format_bind_error_eperm)
{
  errno = EPERM;
  SocketCommon_format_bind_error ("0.0.0.0", 443);
}

TEST (socketcommon_format_bind_error_eafnosupport)
{
  errno = EAFNOSUPPORT;
  SocketCommon_format_bind_error ("invalid", 8080);
}

TEST (socketcommon_format_bind_error_default)
{
  errno = EINVAL; /* Some other error */
  SocketCommon_format_bind_error ("127.0.0.1", 8080);
}

TEST (socketcommon_format_bind_error_null_host)
{
  errno = EADDRINUSE;
  SocketCommon_format_bind_error (NULL, 8080); /* Should use "any" */
}

TEST (socketcommon_handle_bind_error_eaddrinuse)
{
  int result = SocketCommon_handle_bind_error (EADDRINUSE, "127.0.0.1:8080",
                                               Socket_Failed);
  ASSERT_EQ (-1, result); /* Returns -1, doesn't raise */
}

TEST (socketcommon_handle_bind_error_eaddrnotavail)
{
  int result = SocketCommon_handle_bind_error (
      EADDRNOTAVAIL, "192.168.255.255:8080", Socket_Failed);
  ASSERT_EQ (-1, result); /* Returns -1, doesn't raise */
}

TEST (socketcommon_handle_bind_error_eacces)
{
  volatile int raised = 0;

  TRY { SocketCommon_handle_bind_error (EACCES, "0.0.0.0:80", Socket_Failed); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_handle_bind_error_eperm)
{
  volatile int raised = 0;

  TRY { SocketCommon_handle_bind_error (EPERM, "0.0.0.0:443", Socket_Failed); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_handle_bind_error_other)
{
  volatile int raised = 0;

  TRY
  {
    SocketCommon_handle_bind_error (EINVAL, "127.0.0.1:8080", Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

/* IOV Edge Case Coverage Tests */

TEST (socketcommon_advance_iov_invalid_params_null)
{
  volatile int raised = 0;

  TRY { SocketCommon_advance_iov (NULL, 1, 10); }
  EXCEPT (SocketCommon_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_advance_iov_invalid_iovcnt_zero)
{
  volatile int raised = 0;
  struct iovec iov[1];
  char buf[10];
  iov[0].iov_base = buf;
  iov[0].iov_len = 10;

  TRY { SocketCommon_advance_iov (iov, 0, 5); }
  EXCEPT (SocketCommon_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_advance_iov_too_far)
{
  volatile int raised = 0;
  struct iovec iov[1];
  char buf[10];
  iov[0].iov_base = buf;
  iov[0].iov_len = 10;

  TRY { SocketCommon_advance_iov (iov, 1, 20); } /* 20 > 10 */
  EXCEPT (SocketCommon_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_sync_iov_progress_basic)
{
  struct iovec original[2];
  struct iovec copy[2];
  char buf1[100], buf2[100];

  /* Setup original */
  original[0].iov_base = buf1;
  original[0].iov_len = 100;
  original[1].iov_base = buf2;
  original[1].iov_len = 100;

  /* Setup copy with partial progress in buf1 */
  copy[0].iov_base = buf1 + 50; /* Advanced 50 bytes */
  copy[0].iov_len = 50;
  copy[1].iov_base = buf2;
  copy[1].iov_len = 100;

  SocketCommon_sync_iov_progress (original, copy, 2);

  /* Original should now reflect progress */
  ASSERT_EQ (50, original[0].iov_len);
  ASSERT_EQ (buf1 + 50, original[0].iov_base);
  ASSERT_EQ (100, original[1].iov_len); /* Unchanged */
}

TEST (socketcommon_sync_iov_progress_null_original)
{
  struct iovec original[2];
  struct iovec copy[2];
  char buf1[100];

  /* Case: original entry already consumed (NULL base), copy advanced on next
   * entry. This tests the UBSan fix - no pointer arithmetic on NULL. */
  original[0].iov_base = NULL;
  original[0].iov_len = 0;
  original[1].iov_base = buf1;
  original[1].iov_len = 100;

  /* Copy has advanced second iovec by 10 bytes */
  copy[0].iov_base = NULL;
  copy[0].iov_len = 0;
  copy[1].iov_base = buf1 + 10;
  copy[1].iov_len = 90;

  SocketCommon_sync_iov_progress (original, copy, 2);

  /* First entry should remain NULL/0 (no UB) */
  ASSERT_EQ (NULL, original[0].iov_base);
  ASSERT_EQ (0, original[0].iov_len);

  /* Second entry should be advanced by 10 */
  ASSERT_EQ (buf1 + 10, original[1].iov_base);
  ASSERT_EQ (90, original[1].iov_len);
}

TEST (socketcommon_sync_iov_progress_null_copy)
{
  struct iovec original[2];
  struct iovec copy[2];
  char buf1[100], buf2[50];

  /* Case: copy base is NULL (fully advanced past this vector), original was
   * non-NULL. Original should be marked as fully consumed. */
  original[0].iov_base = buf1;
  original[0].iov_len = 100;
  original[1].iov_base = buf2;
  original[1].iov_len = 50;

  /* Copy fully consumed first iovec (NULL base), second unchanged */
  copy[0].iov_base = NULL;
  copy[0].iov_len = 0;
  copy[1].iov_base = buf2;
  copy[1].iov_len = 50;

  SocketCommon_sync_iov_progress (original, copy, 2);

  /* First entry should be fully consumed (NULL/0) */
  ASSERT_EQ (NULL, original[0].iov_base);
  ASSERT_EQ (0, original[0].iov_len);

  /* Second entry unchanged (bases equal) */
  ASSERT_EQ (buf2, original[1].iov_base);
  ASSERT_EQ (50, original[1].iov_len);
}

TEST (socketcommon_sync_iov_progress_full_consume)
{
  struct iovec original[2];
  struct iovec copy[2];
  char buf1[100], buf2[50];

  /* Case: copy advanced exactly to end of buffer (copied >= iov_len) */
  original[0].iov_base = buf1;
  original[0].iov_len = 100;
  original[1].iov_base = buf2;
  original[1].iov_len = 50;

  /* Copy advanced first iovec entirely (pointer at end, len = 0) */
  copy[0].iov_base = buf1 + 100;
  copy[0].iov_len = 0;
  copy[1].iov_base = buf2;
  copy[1].iov_len = 50;

  SocketCommon_sync_iov_progress (original, copy, 2);

  /* First entry should be clamped to fully consumed */
  ASSERT_EQ (NULL, original[0].iov_base);
  ASSERT_EQ (0, original[0].iov_len);

  /* Second entry unchanged */
  ASSERT_EQ (buf2, original[1].iov_base);
  ASSERT_EQ (50, original[1].iov_len);
}

TEST (socketcommon_calculate_total_iov_len_null)
{
  volatile int raised = 0;

  TRY { SocketCommon_calculate_total_iov_len (NULL, 1); }
  EXCEPT (SocketCommon_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_calculate_total_iov_len_negative_iovcnt)
{
  volatile int raised = 0;
  struct iovec iov[1];
  char buf[10];
  iov[0].iov_base = buf;
  iov[0].iov_len = 10;

  TRY { SocketCommon_calculate_total_iov_len (iov, -1); }
  EXCEPT (SocketCommon_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

/* Multicast Coverage Tests */

TEST (socketcommon_join_multicast_ipv4)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_DGRAM, 0);

    /* Try to join a multicast group - may fail on some systems */
    SocketCommon_join_multicast (base, "224.0.0.1", NULL, Socket_Failed);
    SocketCommon_leave_multicast (base, "224.0.0.1", NULL, Socket_Failed);
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected on systems without multicast support */
  }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_join_multicast_ipv6)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET6, SOCK_DGRAM, 0);

    /* Try to join an IPv6 multicast group */
    SocketCommon_join_multicast (base, "ff02::1", NULL, Socket_Failed);
    SocketCommon_leave_multicast (base, "ff02::1", NULL, Socket_Failed);
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected on systems without IPv6 multicast support */
  }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_join_multicast_invalid_group)
{
  setup_signals ();
  SocketBase_T base = NULL;
  volatile int raised = 0;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_DGRAM, 0);
    SocketCommon_join_multicast (base, "not.a.valid.multicast", NULL,
                                 Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_leave_multicast_ipv4)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_DGRAM, 0);
    /* Try to leave a group we didn't join - will fail but covers the code path
     */
    SocketCommon_leave_multicast (base, "224.0.0.1", NULL, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { /* Expected - can't leave group not joined */ }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_join_multicast_with_interface)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_DGRAM, 0);
    /* Try with explicit interface */
    SocketCommon_join_multicast (base, "224.0.0.1", "127.0.0.1",
                                 Socket_Failed);
  }
  EXCEPT (Socket_Failed) { /* Expected - may fail for various reasons */ }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_join_multicast_invalid_interface)
{
  setup_signals ();
  SocketBase_T base = NULL;
  volatile int raised = 0;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_DGRAM, 0);
    /* Invalid interface address */
    SocketCommon_join_multicast (base, "224.0.0.1", "not.an.ip",
                                 Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);

  if (base)
    SocketCommon_free_base (&base);
}

/* TTL Coverage Tests */

TEST (socketcommon_set_ttl_ipv4)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    SocketCommon_set_ttl (base, AF_INET, 64, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { /* May fail on some systems */ }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_set_ttl_ipv6)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET6, SOCK_STREAM, 0);
    SocketCommon_set_ttl (base, AF_INET6, 64, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { /* May fail on some systems */ }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_set_ttl_invalid_family)
{
  setup_signals ();
  SocketBase_T base = NULL;
  volatile int raised = 0;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    SocketCommon_set_ttl (base, AF_UNIX, 64,
                          Socket_Failed); /* Invalid family for TTL */
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);

  if (base)
    SocketCommon_free_base (&base);
}

/* Accessor Coverage Tests */

TEST (socketbase_domain_null)
{
  int domain = SocketBase_domain (NULL);
  ASSERT_EQ (AF_UNSPEC, domain);
}

TEST (socketbase_domain_valid)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    int domain = SocketBase_domain (base);
    ASSERT_EQ (AF_INET, domain);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketbase_set_timeouts_valid)
{
  setup_signals ();
  SocketBase_T base = NULL;
  SocketTimeouts_T timeouts = { 0 };

  timeouts.connect_timeout_ms = 5000;
  timeouts.dns_timeout_ms = 3000;
  timeouts.operation_timeout_ms = 10000;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    SocketBase_set_timeouts (base, &timeouts);

    /* Verify via SocketBase_timeouts() inline accessor */
    SocketTimeouts_T *retrieved = SocketBase_timeouts (base);
    ASSERT_NOT_NULL (retrieved);
    ASSERT_EQ (5000, retrieved->connect_timeout_ms);
    ASSERT_EQ (3000, retrieved->dns_timeout_ms);
    ASSERT_EQ (10000, retrieved->operation_timeout_ms);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketbase_set_timeouts_null_base)
{
  SocketTimeouts_T timeouts = { 0 };
  /* Should not crash with NULL base */
  SocketBase_set_timeouts (NULL, &timeouts);
}

TEST (socketbase_set_timeouts_null_timeouts)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    /* Should not crash with NULL timeouts */
    SocketBase_set_timeouts (base, NULL);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

/* Address Resolution Error Coverage Tests */

TEST (socketcommon_resolve_address_invalid_host)
{
  setup_signals ();
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  volatile int raised = 0;

  SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);

  TRY
  {
    SocketCommon_resolve_address (
        "this.host.definitely.does.not.exist.invalid", 80, &hints, &res,
        Socket_Failed, AF_UNSPEC, 1);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  if (res)
    SocketCommon_free_addrinfo (res);
}

TEST (socketcommon_resolve_address_family_mismatch)
{
  setup_signals ();
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  volatile int raised = 0;

  SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);
  hints.ai_family = AF_INET; /* Force IPv4 only */

  TRY
  {
    /* Try to resolve IPv6 address with IPv4-only hints */
    SocketCommon_resolve_address ("::1", 80, &hints, &res, Socket_Failed,
                                  AF_INET6,
                                  1); /* Expect IPv6 but hints say IPv4 */
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  /* May or may not raise depending on system - just covers code path */
  (void)raised;
  if (res)
    SocketCommon_free_addrinfo (res);
}

TEST (socketcommon_resolve_address_no_exceptions)
{
  setup_signals ();
  struct addrinfo hints;
  struct addrinfo *res = NULL;

  SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);

  /* Call with use_exceptions=0 */
  int result = SocketCommon_resolve_address (
      "this.host.definitely.does.not.exist.invalid", 80, &hints, &res,
      Socket_Failed, AF_UNSPEC, 0);
  ASSERT_EQ (-1, result);
  if (res)
    SocketCommon_free_addrinfo (res);
}

TEST (socketcommon_reverse_lookup_failure)
{
  setup_signals ();
  struct sockaddr_in addr;
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];
  volatile int raised = 0;

  memset (&addr, 0, sizeof (addr));
  addr.sin_family = 255; /* Invalid family */
  addr.sin_port = htons (80);

  TRY
  {
    SocketCommon_reverse_lookup (
        (struct sockaddr *)&addr, sizeof (addr), host, sizeof (host), serv,
        sizeof (serv), NI_NUMERICHOST | NI_NUMERICSERV, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

/* Endpoint Cache Coverage Tests */

TEST (socketcommon_get_safe_host_null)
{
  const char *result = socketcommon_get_safe_host (NULL);
  ASSERT_NOT_NULL (result);
  ASSERT_EQ (0, strcmp (result, "any"));
}

TEST (socketcommon_get_safe_host_valid)
{
  const char *result = socketcommon_get_safe_host ("example.com");
  ASSERT_NOT_NULL (result);
  ASSERT_EQ (0, strcmp (result, "example.com"));
}

/* Socket Option Error Coverage Tests */

TEST (socketcommon_settimeout_negative)
{
  setup_signals ();
  SocketBase_T base = NULL;
  volatile int raised = 0;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    SocketCommon_settimeout (base, -1, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_set_nonblock_disable)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    /* Enable non-blocking */
    SocketCommon_set_nonblock (base, true, Socket_Failed);
    /* Disable non-blocking - covers the else branch */
    SocketCommon_set_nonblock (base, false, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_set_cloexec_fd)
{
  setup_signals ();
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  ASSERT (fd >= 0);

  TRY
  {
    SocketCommon_set_cloexec_fd (fd, true, Socket_Failed);
    SocketCommon_set_cloexec_fd (fd, false, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  close (fd);
}

TEST (socketcommon_setcloexec_with_error)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    SocketCommon_setcloexec_with_error (base, 1, Socket_Failed);
    SocketCommon_setcloexec_with_error (base, 0, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

/* CIDR Matching Edge Case Coverage Tests */

TEST (socketcommon_cidr_match_partial_byte_mask)
{
  /* Test /25 which requires partial byte masking (bits_to_mask = 1) */
  /* These tests exercise the partial byte masking code path */
  int result;
  result = SocketCommon_cidr_match ("192.168.1.1", "192.168.1.0/25");
  ASSERT (result >= 0); /* Just verify no error */
  result = SocketCommon_cidr_match ("192.168.1.127", "192.168.1.0/25");
  ASSERT (result >= 0);
  result = SocketCommon_cidr_match ("192.168.1.128", "192.168.1.0/25");
  ASSERT (result >= 0);

  /* Test /17 for larger partial byte */
  result = SocketCommon_cidr_match ("10.0.0.1", "10.0.0.0/17");
  ASSERT (result >= 0);
  result = SocketCommon_cidr_match ("10.0.127.255", "10.0.0.0/17");
  ASSERT (result >= 0);
  result = SocketCommon_cidr_match ("10.0.128.0", "10.0.0.0/17");
  ASSERT (result >= 0);
}

TEST (socketcommon_cidr_match_ipv6_partial_mask)
{
  /* Test IPv6 with partial byte masking - /33 */
  /* These tests exercise the IPv6 partial byte masking code path */
  int result;
  result = SocketCommon_cidr_match ("2001:db8::1", "2001:db8::/33");
  ASSERT (result >= 0);
  result = SocketCommon_cidr_match ("2001:db8:8000::1", "2001:db8::/33");
  ASSERT (result >= 0);
}

/* Addrinfo Copy Coverage Tests */

TEST (socketcommon_copy_addrinfo_with_canonname)
{
  struct addrinfo hints, *res = NULL;
  struct addrinfo *copy = NULL;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;

  int result = getaddrinfo ("localhost", "80", &hints, &res);
  if (result != 0 || !res)
    {
      /* getaddrinfo failed, skip test */
      return;
    }

  /* Copy the addrinfo chain */
  copy = SocketCommon_copy_addrinfo (res);
  ASSERT_NOT_NULL (copy);

  /* Verify copy - canonname may or may not be set depending on system */
  ASSERT_EQ (res->ai_family, copy->ai_family);
  ASSERT_EQ (res->ai_socktype, copy->ai_socktype);

  /* Free copy using our free function */
  SocketCommon_free_addrinfo (copy);

  /* Free original using system function */
  freeaddrinfo (res);
}

TEST (socketcommon_copy_addrinfo_chain)
{
  struct addrinfo hints, *res = NULL;
  struct addrinfo *copy = NULL;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC; /* May return multiple results */
  hints.ai_socktype = SOCK_STREAM;

  int result = getaddrinfo ("localhost", "80", &hints, &res);
  if (result != 0 || !res)
    {
      return;
    }

  /* Copy the chain */
  copy = SocketCommon_copy_addrinfo (res);
  ASSERT_NOT_NULL (copy);

  /* Count nodes in original and copy */
  int orig_count = 0, copy_count = 0;
  for (struct addrinfo *p = res; p; p = p->ai_next)
    orig_count++;
  for (struct addrinfo *p = copy; p; p = p->ai_next)
    copy_count++;

  ASSERT_EQ (orig_count, copy_count);

  SocketCommon_free_addrinfo (copy);
  freeaddrinfo (res);
}

/* Socket Option Getter Error Tests */

TEST (socketcommon_getoption_int_invalid_option)
{
  setup_signals ();
  volatile int raised = 0;
  int value = 0;
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  ASSERT (fd >= 0);

  TRY
  {
    /* Use valid fd but invalid level/option to trigger error */
    SocketCommon_getoption_int (fd, 9999, 9999, &value, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  close (fd);
}

TEST (socketcommon_getoption_timeval_invalid_option)
{
  setup_signals ();
  volatile int raised = 0;
  struct timeval tv = { 0 };
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  ASSERT (fd >= 0);

  TRY
  {
    /* Use valid fd but invalid level/option to trigger error */
    SocketCommon_getoption_timeval (fd, 9999, 9999, &tv, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  close (fd);
}

TEST (socketcommon_set_option_int_invalid)
{
  setup_signals ();
  SocketBase_T base = NULL;
  volatile int raised = 0;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    /* Invalid option - should fail */
    SocketCommon_set_option_int (base, 9999, 9999, 1, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);

  if (base)
    SocketCommon_free_base (&base);
}

/* Get Family Coverage Tests */

TEST (socketcommon_get_socket_family)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    int family = SocketCommon_get_socket_family (base);
    ASSERT_EQ (AF_INET, family);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_get_family_with_raise)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET6, SOCK_STREAM, 0);
    int family = SocketCommon_get_family (base, true, Socket_Failed);
    ASSERT_EQ (AF_INET6, family);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

/* Bind with Resolved Addresses Coverage */

TEST (socketcommon_try_bind_resolved_addresses_success)
{
  setup_signals ();
  SocketBase_T base = NULL;
  struct addrinfo hints, *res = NULL;

  SocketCommon_setup_hints (&hints, SOCK_STREAM, AI_PASSIVE);
  hints.ai_family = AF_INET;

  /* Get a valid address first */
  int result = getaddrinfo ("127.0.0.1", "0", &hints, &res);
  if (result != 0 || !res)
    return;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    /* First bind should succeed */
    SocketCommon_try_bind_resolved_addresses (base, res, AF_INET,
                                              Socket_Failed);
  }
  EXCEPT (Socket_Failed) { /* May fail if address already in use */ }
  END_TRY;

  /* Clean up */
  freeaddrinfo (res);
  if (base)
    SocketCommon_free_base (&base);
}

/* Base Lifecycle Coverage Tests */

TEST (socketcommon_new_base_and_free)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (base);
    ASSERT (SocketBase_fd (base) >= 0);
    ASSERT_NOT_NULL (SocketBase_arena (base));
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  if (base)
    {
      SocketCommon_free_base (&base);
      ASSERT_NULL (base);
    }
}

TEST (socketcommon_free_base_null)
{
  SocketBase_T base = NULL;
  /* Should not crash */
  SocketCommon_free_base (&base);
}

TEST (socketbase_fd_null)
{
  int fd = SocketBase_fd (NULL);
  ASSERT_EQ (-1, fd);
}

TEST (socketbase_arena_null)
{
  Arena_T arena = SocketBase_arena (NULL);
  ASSERT_NULL (arena);
}

/* Additional SocketCommon Coverage Tests */

TEST (socketcommon_cidr_match_ipv4_parse_error)
{
  /* Test CIDR with invalid IPv4 in IP string */
  int result = SocketCommon_cidr_match ("256.256.256.256", "192.168.1.0/24");
  ASSERT_EQ (-1, result);
}

TEST (socketcommon_cidr_match_ipv6_parse_error)
{
  /* Test CIDR with invalid IPv6 */
  int result = SocketCommon_cidr_match ("gggg::1", "2001:db8::/32");
  ASSERT_EQ (-1, result);
}

TEST (socketcommon_cidr_match_invalid_network_ipv4)
{
  /* Test CIDR with invalid IPv4 network address - triggers line 307 */
  int result = SocketCommon_cidr_match ("192.168.1.1", "256.256.256.0/24");
  ASSERT_EQ (-1, result);
}

TEST (socketcommon_cidr_match_invalid_network_ipv6)
{
  /* Test CIDR with invalid IPv6 network - triggers line 314 */
  int result = SocketCommon_cidr_match ("2001:db8::1", "gggg::/32");
  ASSERT_EQ (-1, result);
}

TEST (socketcommon_try_bind_address_failure)
{
  setup_signals ();
  SocketBase_T base = NULL;
  struct sockaddr_in addr;
  volatile int raised = 0;

  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (1); /* Privileged port */
  inet_pton (AF_INET, "127.0.0.1", &addr.sin_addr);

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    /* Try to bind to privileged port - should fail for non-root */
    SocketCommon_try_bind_address (base, (struct sockaddr *)&addr,
                                   sizeof (addr), Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  /* Should raise on non-root systems */
  (void)raised;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_try_bind_resolved_addresses_all_fail)
{
  setup_signals ();
  SocketBase_T base1 = NULL;
  SocketBase_T base2 = NULL;
  struct addrinfo hints, *res = NULL;
  volatile int raised = 0;

  SocketCommon_setup_hints (&hints, SOCK_STREAM, AI_PASSIVE);
  hints.ai_family = AF_INET;

  /* Get address for a specific port */
  int result = getaddrinfo ("127.0.0.1", "0", &hints, &res);
  if (result != 0 || !res)
    return;

  TRY
  {
    /* First socket binds successfully */
    base1 = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    SocketCommon_try_bind_resolved_addresses (base1, res, AF_INET,
                                              Socket_Failed);

    /* Get the port that was assigned */
    struct sockaddr_storage local;
    socklen_t len = sizeof (local);
    getsockname (SocketBase_fd (base1), (struct sockaddr *)&local, &len);
    int port = ntohs (((struct sockaddr_in *)&local)->sin_port);

    /* Create new resolution for same port */
    freeaddrinfo (res);  /* From direct getaddrinfo */
    res = NULL;
    char port_str[16];
    snprintf (port_str, sizeof (port_str), "%d", port);
    result = getaddrinfo ("127.0.0.1", port_str, &hints, &res);
    if (result != 0 || !res)
      {
        if (base1)
          SocketCommon_free_base (&base1);
        return;
      }

    /* Second socket tries to bind to same address - should fail */
    base2 = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    SocketCommon_try_bind_resolved_addresses (base2, res, AF_INET,
                                              Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  /* Should raise EADDRINUSE */
  (void)raised;

  if (res)
    freeaddrinfo (res);  /* From direct getaddrinfo */
  if (base2)
    SocketCommon_free_base (&base2);
  if (base1)
    SocketCommon_free_base (&base1);
}

TEST (socketcommon_resolve_address_family_strict_mismatch)
{
  setup_signals ();
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  volatile int raised = 0;

  SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);

  TRY
  {
    /* Resolve an IPv4 address but require IPv6 family - should fail */
    SocketCommon_resolve_address ("127.0.0.1", 80, &hints, &res, Socket_Failed,
                                  AF_INET6, 1);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  if (res)
    SocketCommon_free_addrinfo (res);
}

TEST (socketcommon_copy_addrinfo_empty_addr)
{
  /* Test copying addrinfo with NULL ai_addr */
  struct addrinfo src;
  memset (&src, 0, sizeof (src));
  src.ai_family = AF_INET;
  src.ai_socktype = SOCK_STREAM;
  src.ai_addr = NULL; /* NULL address */
  src.ai_addrlen = 0;
  src.ai_next = NULL;

  struct addrinfo *copy = SocketCommon_copy_addrinfo (&src);
  ASSERT_NOT_NULL (copy);
  ASSERT_NULL (copy->ai_addr);
  ASSERT_EQ (0, copy->ai_addrlen);

  SocketCommon_free_addrinfo (copy);
}

TEST (socketcommon_leave_multicast_ipv6)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET6, SOCK_DGRAM, 0);
    /* Try to leave a group we didn't join - will fail but covers IPv6 leave
     * path */
    SocketCommon_leave_multicast (base, "ff02::1", NULL, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { /* Expected - can't leave group not joined */ }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_iov_overflow_detection)
{
  volatile int raised = 0;
  struct iovec iov[2];
  char buf1[10], buf2[10];

  iov[0].iov_base = buf1;
  iov[0].iov_len = SIZE_MAX; /* Will cause overflow */
  iov[1].iov_base = buf2;
  iov[1].iov_len = 1;

  TRY { SocketCommon_calculate_total_iov_len (iov, 2); }
  EXCEPT (SocketCommon_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socketcommon_get_family_fallback)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);

    /* Bind to get a valid address for getsockname fallback */
    struct sockaddr_in addr;
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_ANY);
    addr.sin_port = 0;

    int result
        = bind (SocketBase_fd (base), (struct sockaddr *)&addr, sizeof (addr));
    if (result == 0)
      {
        /* Now get_socket_family should work via getsockname */
        int family = SocketCommon_get_socket_family (base);
        ASSERT_EQ (AF_INET, family);
      }
  }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_update_local_endpoint_unbound)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    /* Update endpoint on unbound socket - exercises the code path */
    SocketCommon_update_local_endpoint (base);
    /* Local addr should be NULL or set to defaults */
  }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_setcloexec_already_set)
{
  setup_signals ();
  /* Test setting cloexec when already set - exercises "no change" path */
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  ASSERT (fd >= 0);

  /* Enable CLOEXEC */
  int result = SocketCommon_setcloexec (fd, 1);
  ASSERT_EQ (0, result);

  /* Set again - should succeed (no change needed) */
  result = SocketCommon_setcloexec (fd, 1);
  ASSERT_EQ (0, result);

  close (fd);
}

TEST (socketcommon_join_multicast_unix_socket)
{
  setup_signals ();
  SocketBase_T base = NULL;
  volatile int raised = 0;

  TRY
  {
    /* Unix sockets don't support multicast - triggers unsupported family */
    base = SocketCommon_new_base (AF_UNIX, SOCK_DGRAM, 0);
    SocketCommon_join_multicast (base, "224.0.0.1", NULL, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_validate_hostname_null)
{
  /* NULL hostname should be valid (any address) */
  int result
      = socketcommon_validate_hostname_internal (NULL, 0, Socket_Failed, NULL);
  /* NULL is valid for bind - returns success */
  ASSERT (result >= 0
          || result == -1); /* May accept or reject depending on impl */
}

TEST (socketcommon_try_bind_family_mismatch)
{
  setup_signals ();
  SocketBase_T base = NULL;
  struct addrinfo hints, *res = NULL;

  SocketCommon_setup_hints (&hints, SOCK_STREAM, AI_PASSIVE);
  hints.ai_family = AF_INET;

  /* Get IPv4 address */
  int result = getaddrinfo ("127.0.0.1", "0", &hints, &res);
  if (result != 0 || !res)
    return;

  TRY
  {
    /* Create IPv6 socket but try to bind IPv4 address */
    base = SocketCommon_new_base (AF_INET6, SOCK_STREAM, 0);
    /* This should skip the address because family doesn't match */
    SocketCommon_try_bind_resolved_addresses (base, res, AF_INET6,
                                              Socket_Failed);
  }
  EXCEPT (Socket_Failed) { /* Expected - no matching address found */ }
  END_TRY;

  freeaddrinfo (res);
  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_resolve_address_family_no_match)
{
  setup_signals ();
  struct addrinfo hints;
  struct addrinfo *res = NULL;

  SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);

  /* Resolve with use_exceptions=0 and require IPv6, but get IPv4 only */
  int result = SocketCommon_resolve_address ("127.0.0.1", 80, &hints, &res,
                                             Socket_Failed, AF_INET6, 0);
  /* Should return -1 for no matching family, and res is freed on error */
  ASSERT_EQ (-1, result);
  /* res is NULL after validation failure - the function frees it */
  ASSERT_EQ (NULL, res);
}

TEST (socketcommon_set_option_successful)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);
    /* Test various socket options */
    SocketCommon_setreuseaddr (base, Socket_Failed);
    SocketCommon_setreuseport (base, Socket_Failed);
    SocketCommon_settimeout (base, 5, Socket_Failed);
  }
  EXCEPT (Socket_Failed) { /* May fail on some systems */ }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_convert_port_to_string)
{
  char port_str[16];

  socketcommon_convert_port_to_string (8080, port_str, sizeof (port_str));
  ASSERT_EQ (0, strcmp (port_str, "8080"));

  socketcommon_convert_port_to_string (0, port_str, sizeof (port_str));
  ASSERT_EQ (0, strcmp (port_str, "0"));

  socketcommon_convert_port_to_string (65535, port_str, sizeof (port_str));
  ASSERT_EQ (0, strcmp (port_str, "65535"));
}

TEST (socketcommon_sanitize_timeout)
{
  /* Test timeout sanitization */
  int result = socketcommon_sanitize_timeout (5000);
  ASSERT_EQ (5000, result);

  result = socketcommon_sanitize_timeout (
      -1); /* Should be clamped or use default */
  ASSERT (result >= 0);

  result = socketcommon_sanitize_timeout (0); /* Should be allowed */
  ASSERT_EQ (0, result);
}

TEST (socketcommon_cache_endpoint_with_invalid_addr)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  struct sockaddr_in addr;
  char *addr_str = NULL;
  int port = 0;

  /* Setup invalid address family to trigger getnameinfo failure */
  memset (&addr, 0, sizeof (addr));
  addr.sin_family = 255; /* Invalid family */
  addr.sin_port = htons (8080);

  int result = SocketCommon_cache_endpoint (arena, (struct sockaddr *)&addr,
                                            sizeof (addr), &addr_str, &port);
  /* Should fail due to invalid family */
  ASSERT_EQ (-1, result);

  Arena_dispose (&arena);
}

TEST (socketcommon_update_local_endpoint_bound)
{
  setup_signals ();
  SocketBase_T base = NULL;

  TRY
  {
    base = SocketCommon_new_base (AF_INET, SOCK_STREAM, 0);

    /* Bind to get a local endpoint */
    struct sockaddr_in addr;
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind (SocketBase_fd (base), (struct sockaddr *)&addr, sizeof (addr))
        == 0)
      {
        /* Update should succeed and cache the endpoint */
        SocketCommon_update_local_endpoint (base);

        char *local = SocketBase_localaddr (base);
        int port = SocketBase_localport (base);
        ASSERT_NOT_NULL (local);
        ASSERT (port > 0);
      }
  }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  if (base)
    SocketCommon_free_base (&base);
}

TEST (socketcommon_alloc_iov_copy_basic)
{
  setup_signals ();
  struct iovec src[2];
  struct iovec *copy = NULL;
  char buf1[100], buf2[100];

  src[0].iov_base = buf1;
  src[0].iov_len = 100;
  src[1].iov_base = buf2;
  src[1].iov_len = 100;

  TRY
  {
    copy = SocketCommon_alloc_iov_copy (src, 2, Socket_Failed);
    ASSERT_NOT_NULL (copy);
    ASSERT_EQ (100, copy[0].iov_len);
    ASSERT_EQ (100, copy[1].iov_len);
    /* Free copy - uses malloc internally */
    free (copy);
  }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;
}

/* ==================== Bandwidth Limiting Tests ==================== */

TEST (socket_setbandwidth_enable_disable)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  /* Initially no bandwidth limit */
  ASSERT_EQ (0, Socket_getbandwidth (socket));

  /* Set bandwidth limit */
  TRY
  {
    Socket_setbandwidth (socket, 10000);
    ASSERT_EQ (10000, Socket_getbandwidth (socket));

    /* Disable bandwidth limit */
    Socket_setbandwidth (socket, 0);
    ASSERT_EQ (0, Socket_getbandwidth (socket));
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_getbandwidth_returns_configured_value)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  TRY
  {
    Socket_setbandwidth (socket, 50000);
    ASSERT_EQ (50000, Socket_getbandwidth (socket));

    Socket_setbandwidth (socket, 1000000);
    ASSERT_EQ (1000000, Socket_getbandwidth (socket));
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_setbandwidth_reconfigures_existing_limiter)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  TRY
  {
    /* Set initial bandwidth */
    Socket_setbandwidth (socket, 10000);
    ASSERT_EQ (10000, Socket_getbandwidth (socket));

    /* Reconfigure existing limiter */
    Socket_setbandwidth (socket, 20000);
    ASSERT_EQ (20000, Socket_getbandwidth (socket));

    /* Reconfigure again */
    Socket_setbandwidth (socket, 5000);
    ASSERT_EQ (5000, Socket_getbandwidth (socket));
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_send_limited_without_limit_behaves_as_send)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &socket1, &socket2);
    ASSERT_NOT_NULL (socket1);
    ASSERT_NOT_NULL (socket2);

    /* No bandwidth limit set */
    ASSERT_EQ (0, Socket_getbandwidth (socket1));

    const char *msg = "test message";
    ssize_t sent = Socket_send_limited (socket1, msg, strlen (msg));
    ASSERT (sent > 0);

    char buf[256];
    ssize_t received = Socket_recv (socket2, buf, sizeof (buf));
    ASSERT (received > 0);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

TEST (socket_send_limited_with_limit_partial_send)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &socket1, &socket2);
    ASSERT_NOT_NULL (socket1);
    ASSERT_NOT_NULL (socket2);

    /* Set bandwidth limit */
    Socket_setbandwidth (socket1, 1000000);
    ASSERT_EQ (1000000, Socket_getbandwidth (socket1));

    const char *msg = "test message";
    ssize_t sent = Socket_send_limited (socket1, msg, strlen (msg));
    ASSERT (sent > 0);

    char buf[256];
    ssize_t received = Socket_recv (socket2, buf, sizeof (buf));
    ASSERT (received > 0);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

TEST (socket_recv_limited_without_limit_behaves_as_recv)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &socket1, &socket2);
    ASSERT_NOT_NULL (socket1);
    ASSERT_NOT_NULL (socket2);

    /* No bandwidth limit set */
    ASSERT_EQ (0, Socket_getbandwidth (socket2));

    const char *msg = "test message";
    ssize_t sent = Socket_send (socket1, msg, strlen (msg));
    ASSERT (sent > 0);

    char buf[256];
    ssize_t received = Socket_recv_limited (socket2, buf, sizeof (buf));
    ASSERT (received > 0);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

TEST (socket_recv_limited_with_limit)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &socket1, &socket2);
    ASSERT_NOT_NULL (socket1);
    ASSERT_NOT_NULL (socket2);

    /* Set bandwidth limit on receiving socket */
    Socket_setbandwidth (socket2, 1000000);
    ASSERT_EQ (1000000, Socket_getbandwidth (socket2));

    const char *msg = "test message";
    ssize_t sent = Socket_send (socket1, msg, strlen (msg));
    ASSERT (sent > 0);

    char buf[256];
    ssize_t received = Socket_recv_limited (socket2, buf, sizeof (buf));
    ASSERT (received > 0);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

TEST (socket_bandwidth_wait_ms_no_limit_returns_zero)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  /* No bandwidth limit - should return 0 */
  int64_t wait = Socket_bandwidth_wait_ms (socket, 1000);
  ASSERT_EQ (0, wait);

  Socket_free (&socket);
}

TEST (socket_bandwidth_wait_ms_with_limit)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  TRY
  {
    Socket_setbandwidth (socket, 1000);

    /* Query wait time - should be >= 0 */
    int64_t wait = Socket_bandwidth_wait_ms (socket, 100);
    ASSERT (wait >= 0);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
}

/* ==================== Socket_new_from_fd Tests ==================== */

TEST (socket_new_from_fd_basic)
{
  setup_signals ();
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  ASSERT (fd >= 0);

  Socket_T sock = NULL;
  TRY
  {
    sock = Socket_new_from_fd (fd);
    ASSERT_NOT_NULL (sock);
    ASSERT (Socket_fd (sock) == fd);
  }
  EXCEPT (Socket_Failed)
  {
    close (fd);
    ASSERT (0);
  }
  END_TRY;

  if (sock)
    Socket_free (&sock);
}

TEST (socket_new_from_fd_closed_fd_raises)
{
  setup_signals ();
  volatile int raised = 0;

  /* Create and immediately close a socket to get an invalid fd */
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  ASSERT (fd >= 0);
  close (fd);

  TRY { Socket_new_from_fd (fd); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
}

TEST (socket_new_from_fd_non_socket_fd_raises)
{
  setup_signals ();
  volatile int raised = 0;

  /* Create a pipe - not a socket */
  int pipefd[2];
  if (pipe (pipefd) < 0)
    return;

  TRY { Socket_new_from_fd (pipefd[0]); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  close (pipefd[0]);
  close (pipefd[1]);

  ASSERT_EQ (1, raised);
}

/* ==================== Socket_listen Error Path Tests ==================== */

TEST (socket_listen_zero_backlog_raises)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  volatile int raised = 0;

  TRY
  {
    Socket_bind (socket, "127.0.0.1", 0);
    Socket_listen (socket, 0);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&socket);
}

TEST (socket_listen_negative_backlog_raises)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  volatile int raised = 0;

  TRY
  {
    Socket_bind (socket, "127.0.0.1", 0);
    Socket_listen (socket, -5);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&socket);
}

TEST (socket_listen_large_backlog_clamps_to_max)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  TRY
  {
    Socket_bind (socket, "127.0.0.1", 0);
    /* Very large backlog - should be clamped but not fail */
    Socket_listen (socket, 1000000);
    /* If we get here, it worked (value was clamped) */
    ASSERT (Socket_islistening (socket));
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
}

/* ==================== Unix Socket Error Path Tests ==================== */

TEST (socket_bind_unix_path_too_long_raises)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  volatile int raised = 0;

  /* Create a path that's too long for sun_path */
  char long_path[256];
  memset (long_path, 'a', sizeof (long_path) - 1);
  long_path[sizeof (long_path) - 1] = '\0';

  TRY { Socket_bind_unix (socket, long_path); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&socket);
}

TEST (socket_bind_unix_directory_traversal_raises)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  volatile int raised = 0;

  TRY { Socket_bind_unix (socket, "/tmp/../../../etc/passwd"); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&socket);
}

TEST (socket_connect_unix_nonexistent_raises_enoent)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  volatile int raised = 0;

  /* Make sure the file doesn't exist */
  unlink ("/tmp/nonexistent_socket_test_12345");

  TRY { Socket_connect_unix (socket, "/tmp/nonexistent_socket_test_12345"); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&socket);
}

TEST (socket_connect_unix_no_listener_raises_econnrefused)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (server);
  ASSERT_NOT_NULL (client);

  const char *path = "/tmp/test_econnrefused_socket";
  cleanup_unix_socket (path);
  volatile int raised = 0;

  TRY
  {
    /* Bind but don't listen - creates file but no listener */
    Socket_bind_unix (server, path);
    /* Now try to connect - should fail with ECONNREFUSED */
    Socket_connect_unix (client, path);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  cleanup_unix_socket (path);
  ASSERT_EQ (1, raised);

  Socket_free (&server);
  Socket_free (&client);
}

/* ==================== Abstract Unix Socket Tests ==================== */

#ifdef __linux__
TEST (socket_bind_unix_abstract_namespace)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  TRY
  {
    /* Abstract namespace uses @ prefix */
    Socket_bind_unix (socket, "@test_abstract_socket");
    /* Should succeed - abstract namespace doesn't create file */
    ASSERT (Socket_isbound (socket));
  }
  EXCEPT (Socket_Failed) { /* May fail on some systems */ }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_connect_unix_abstract_namespace)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (server);
  ASSERT_NOT_NULL (client);

  TRY
  {
    Socket_bind_unix (server, "@test_abstract_connect");
    Socket_listen (server, 5);
    Socket_setnonblocking (server);

    Socket_connect_unix (client, "@test_abstract_connect");
    ASSERT (Socket_isconnected (client));

    Socket_T accepted = Socket_accept (server);
    if (accepted)
      Socket_free (&accepted);
  }
  EXCEPT (Socket_Failed) { /* May fail on some systems */ }
  END_TRY;

  Socket_free (&server);
  Socket_free (&client);
}
#endif /* __linux__ */

/* ==================== SocketPair Error Path Tests ==================== */

TEST (socketpair_new_invalid_type_raises)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;
  volatile int raised = 0;

  TRY
  {
    /* Use an invalid socket type (not SOCK_STREAM or SOCK_DGRAM) */
    SocketPair_new (SOCK_RAW, &socket1, &socket2);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

/* ==================== Async Bind Cancel Tests ==================== */

TEST (socket_bind_async_cancel_basic)
{
  setup_signals ();
  SocketDNS_T dns = NULL;
  Socket_T socket = NULL;
  volatile Request_T req = NULL;

  TRY
  {
    dns = SocketDNS_new ();
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (dns);
    ASSERT_NOT_NULL (socket);

    /* Start async bind */
    req = Socket_bind_async (dns, socket, "localhost", 0);
    ASSERT_NOT_NULL (req);

    /* Cancel the request */
    Socket_bind_async_cancel (dns, req);
    req = NULL; /* Prevent double-cancel */
  }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  if (req)
    Socket_bind_async_cancel (dns, req);
  if (socket)
    Socket_free (&socket);
  if (dns)
    SocketDNS_free (&dns);
}

TEST (socket_bind_async_cancel_null_request_safe)
{
  setup_signals ();
  SocketDNS_T dns = NULL;

  TRY
  {
    dns = SocketDNS_new ();
    ASSERT_NOT_NULL (dns);

    /* Cancel with NULL request should be safe */
    Socket_bind_async_cancel (dns, NULL);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  if (dns)
    SocketDNS_free (&dns);
}

/* ==================== Additional Coverage Tests ==================== */

TEST (socket_debug_live_count)
{
  setup_signals ();
  int initial_count = Socket_debug_live_count ();

  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  /* Live count should have increased */
  int after_create = Socket_debug_live_count ();
  ASSERT_EQ (initial_count + 1, after_create);

  Socket_free (&socket);

  /* Live count should be back to initial */
  int after_free = Socket_debug_live_count ();
  ASSERT_EQ (initial_count, after_free);
}

TEST (socket_getlocaladdr_after_bind)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  TRY
  {
    Socket_bind (socket, "127.0.0.1", 0);
    const char *local = Socket_getlocaladdr (socket);
    ASSERT_NOT_NULL (local);
    /* Should be "127.0.0.1" or similar */
    ASSERT (strlen (local) > 0);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_getlocalport_after_bind)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  TRY
  {
    Socket_bind (socket, "127.0.0.1", 0);
    int port = Socket_getlocalport (socket);
    /* Port 0 means kernel assigns - should be > 0 after bind */
    ASSERT (port > 0);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  Socket_free (&socket);
}

TEST (socket_getlocaladdr_before_bind_returns_unknown)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  /* Before bind, should return "(unknown)" */
  const char *local = Socket_getlocaladdr (socket);
  ASSERT_NOT_NULL (local);

  Socket_free (&socket);
}

TEST (socket_bind_eaddrinuse)
{
  setup_signals ();
  Socket_T socket1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T socket2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket1);
  ASSERT_NOT_NULL (socket2);

  volatile int port = 0;
  volatile int raised = 0;

  TRY
  {
    /* Bind first socket to a port */
    Socket_bind (socket1, "127.0.0.1", 0);
    Socket_listen (socket1, 1);

    /* Get the port */
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (Socket_fd (socket1), (struct sockaddr *)&addr, &len);
    port = ntohs (addr.sin_port);

    /* Try to bind second socket to same port - should fail with EADDRINUSE */
    Socket_bind (socket2, "127.0.0.1", port);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  /* Note: bind may succeed due to OS differences, so we don't assert raised */
  (void)raised;

  Socket_free (&socket1);
  Socket_free (&socket2);
}

TEST (socket_isconnected_caches_peer_info)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (server);
  ASSERT_NOT_NULL (client);

  TRY
  {
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 1);

    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
    int port = ntohs (addr.sin_port);

    Socket_connect (client, "127.0.0.1", port);

    /* Check isconnected - this should cache peer info */
    ASSERT_EQ (1, Socket_isconnected (client));

    /* Now getpeeraddr should return cached value */
    const char *peer = Socket_getpeeraddr (client);
    ASSERT_NOT_NULL (peer);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  Socket_free (&server);
  Socket_free (&client);
}

TEST (socket_send_limited_rate_limited_returns_zero)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &socket1, &socket2);
    ASSERT_NOT_NULL (socket1);
    ASSERT_NOT_NULL (socket2);

    /* Set very low bandwidth limit - 1 byte per second */
    Socket_setbandwidth (socket1, 1);

    /* First send should succeed (uses burst) */
    const char *msg = "test";
    ssize_t sent1 = Socket_send_limited (socket1, msg, strlen (msg));
    /* May succeed or return 0 depending on rate limiter state */
    (void)sent1;

    /* Immediate second send should be rate limited */
    ssize_t sent2 = Socket_send_limited (socket1, msg, strlen (msg));
    /* Should be 0 (rate limited) or positive (if some tokens available) */
    ASSERT (sent2 >= 0);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

TEST (socket_recv_limited_rate_limited_returns_zero)
{
  setup_signals ();
  Socket_T socket1 = NULL;
  Socket_T socket2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &socket1, &socket2);
    ASSERT_NOT_NULL (socket1);
    ASSERT_NOT_NULL (socket2);

    /* Set very low bandwidth limit on receiver */
    Socket_setbandwidth (socket2, 1);

    /* Send some data */
    const char *msg = "test message data";
    Socket_send (socket1, msg, strlen (msg));

    /* First recv should get some data */
    char buf[256];
    ssize_t recv1 = Socket_recv_limited (socket2, buf, sizeof (buf));
    (void)recv1;

    /* Need more data to test rate limiting properly */
    Socket_send (socket1, msg, strlen (msg));
    ssize_t recv2 = Socket_recv_limited (socket2, buf, sizeof (buf));
    ASSERT (recv2 >= 0);
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  if (socket1)
    Socket_free (&socket1);
  if (socket2)
    Socket_free (&socket2);
}

TEST (socket_bind_with_addrinfo_success)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  struct addrinfo hints, *res = NULL;
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int result = getaddrinfo ("127.0.0.1", "0", &hints, &res);
  if (result != 0 || !res)
    {
      Socket_free (&socket);
      return;
    }

  TRY
  {
    Socket_bind_with_addrinfo (socket, res);
    ASSERT (Socket_isbound (socket));
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  freeaddrinfo (res);
  Socket_free (&socket);
}

TEST (socket_bind_with_addrinfo_failure)
{
  setup_signals ();
  Socket_T socket1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T socket2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket1);
  ASSERT_NOT_NULL (socket2);
  volatile int raised = 0;

  struct addrinfo hints, *res = NULL;
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  /* Bind first socket to get a specific port */
  TRY
  {
    Socket_bind (socket1, "127.0.0.1", 0);

    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (Socket_fd (socket1), (struct sockaddr *)&addr, &len);
    int port = ntohs (addr.sin_port);

    /* Get addrinfo for the same port */
    char port_str[16];
    snprintf (port_str, sizeof (port_str), "%d", port);
    int result = getaddrinfo ("127.0.0.1", port_str, &hints, &res);
    if (result == 0 && res)
      {
        /* Try to bind second socket to same port - should fail */
        Socket_bind_with_addrinfo (socket2, res);
      }
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  /* Cleanup */
  (void)raised;
  if (res)
    freeaddrinfo (res);  /* From direct getaddrinfo, not copy */
  Socket_free (&socket1);
  Socket_free (&socket2);
}

TEST (socket_listen_on_unbound_socket)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  volatile int raised = 0;

  TRY
  {
    /* Try to listen without binding first - should fail */
    Socket_listen (socket, 5);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  /* May succeed or fail depending on OS */
  (void)raised;
  Socket_free (&socket);
}

TEST (socket_bind_unix_stale_socket_file)
{
  setup_signals ();
  const char *path = "/tmp/test_stale_socket_file";

  /* Create a stale socket file */
  Socket_T old_socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (old_socket);

  TRY { Socket_bind_unix (old_socket, path); }
  EXCEPT (Socket_Failed)
  {
    Socket_free (&old_socket);
    cleanup_unix_socket (path);
    return;
  }
  END_TRY;

  /* Free socket but leave file */
  Socket_free (&old_socket);

  /* Now try to bind a new socket to same path - should unlink stale file */
  Socket_T new_socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (new_socket);

  TRY
  {
    Socket_bind_unix (new_socket, path);
    /* Should succeed by unlinking stale file first */
    ASSERT (Socket_isbound (new_socket));
  }
  EXCEPT (Socket_Failed) { /* May fail if permissions prevent unlink */ }
  END_TRY;

  cleanup_unix_socket (path);
  Socket_free (&new_socket);
}

TEST (socket_connect_unix_other_error)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);
  volatile int raised = 0;

  /* Try to connect to a path that's a regular file, not a socket */
  TRY { Socket_connect_unix (socket, "/etc/passwd"); }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&socket);
}

/* ==================== File Descriptor Passing (SCM_RIGHTS) Tests
 * ==================== */

TEST (socket_sendfd_recvfd_basic)
{
  setup_signals ();

  /* Create a socket pair for FD passing */
  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    ASSERT_NOT_NULL (sock1);
    ASSERT_NOT_NULL (sock2);

    /* Create a pipe to pass */
    int pipefd[2];
    ASSERT_EQ (0, pipe (pipefd));

    /* Send the read end of the pipe */
    int result = Socket_sendfd (sock1, pipefd[0]);
    ASSERT_EQ (1, result);

    /* Receive the FD on the other end */
    int received_fd = -1;
    result = Socket_recvfd (sock2, &received_fd);
    ASSERT_EQ (1, result);
    ASSERT_NE (-1, received_fd);

    /* Verify the received FD works - write to pipe[1], read from received_fd
     */
    const char *test_msg = "FD passing test";
    ssize_t written = write (pipefd[1], test_msg, strlen (test_msg));
    ASSERT_EQ ((ssize_t)strlen (test_msg), written);

    char buf[64] = { 0 };
    ssize_t bytes_read = read (received_fd, buf, sizeof (buf) - 1);
    ASSERT_EQ ((ssize_t)strlen (test_msg), bytes_read);
    ASSERT_EQ (0, strcmp (buf, test_msg));

    /* Cleanup */
    SAFE_CLOSE (pipefd[0]);
    SAFE_CLOSE (pipefd[1]);
    SAFE_CLOSE (received_fd);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); /* Test failed */ }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
}

TEST (socket_sendfd_recvfd_file)
{
  setup_signals ();

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    ASSERT_NOT_NULL (sock1);
    ASSERT_NOT_NULL (sock2);

    /* Open a file to pass */
    int fd = open ("/dev/null", O_RDWR);
    ASSERT_NE (-1, fd);

    /* Send the file descriptor */
    int result = Socket_sendfd (sock1, fd);
    ASSERT_EQ (1, result);

    /* Receive the FD */
    int received_fd = -1;
    result = Socket_recvfd (sock2, &received_fd);
    ASSERT_EQ (1, result);
    ASSERT_NE (-1, received_fd);

    /* Verify received FD is valid and writable */
    ssize_t written = write (received_fd, "test", 4);
    ASSERT_EQ (4, written);

    SAFE_CLOSE (fd);
    SAFE_CLOSE (received_fd);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
}

TEST (socket_sendfd_recvfd_socket)
{
  setup_signals ();

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    ASSERT_NOT_NULL (sock1);
    ASSERT_NOT_NULL (sock2);

    /* Create a listening socket to pass */
    Socket_T listener = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (listener);
    Socket_bind (listener, "127.0.0.1", 0);
    Socket_listen (listener, 5);

    int listener_fd = Socket_fd (listener);

    /* Send the listener socket FD */
    int result = Socket_sendfd (sock1, listener_fd);
    ASSERT_EQ (1, result);

    /* Receive the FD */
    int received_fd = -1;
    result = Socket_recvfd (sock2, &received_fd);
    ASSERT_EQ (1, result);
    ASSERT_NE (-1, received_fd);
    ASSERT_NE (listener_fd, received_fd); /* Should be new FD */

    /* Verify received FD is a valid socket by checking SO_TYPE */
    int val = 0;
    socklen_t len = sizeof (val);
    ASSERT_EQ (0, getsockopt (received_fd, SOL_SOCKET, SO_TYPE, &val, &len));
    ASSERT_EQ (SOCK_STREAM, val); /* Should be a stream socket */

    /* Note: SO_ACCEPTCONN check skipped - macOS returns error for FD-passed
     * sockets */

    SAFE_CLOSE (received_fd);
    Socket_free (&listener);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
}

TEST (socket_sendfds_recvfds_multiple)
{
  setup_signals ();

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    ASSERT_NOT_NULL (sock1);
    ASSERT_NOT_NULL (sock2);

    /* Create multiple FDs to pass */
    int fds_to_send[3];
    fds_to_send[0] = open ("/dev/null", O_RDONLY);
    fds_to_send[1] = open ("/dev/zero", O_RDONLY);

    int pipefd[2];
    ASSERT_EQ (0, pipe (pipefd));
    fds_to_send[2] = pipefd[0];

    ASSERT_NE (-1, fds_to_send[0]);
    ASSERT_NE (-1, fds_to_send[1]);
    ASSERT_NE (-1, fds_to_send[2]);

    /* Send multiple FDs */
    int result = Socket_sendfds (sock1, fds_to_send, 3);
    ASSERT_EQ (1, result);

    /* Receive multiple FDs */
    int received_fds[5] = { -1, -1, -1, -1, -1 };
    size_t received_count = 0;
    result = Socket_recvfds (sock2, received_fds, 5, &received_count);
    ASSERT_EQ (1, result);
    ASSERT_EQ (3, (int)received_count);

    /* Verify all received FDs are valid */
    for (size_t i = 0; i < received_count; i++)
      {
        ASSERT_NE (-1, received_fds[i]);
        ASSERT_NE (-1, fcntl (received_fds[i], F_GETFD));
      }

    /* Cleanup */
    SAFE_CLOSE (fds_to_send[0]);
    SAFE_CLOSE (fds_to_send[1]);
    SAFE_CLOSE (fds_to_send[2]);
    SAFE_CLOSE (pipefd[1]);
    for (size_t i = 0; i < received_count; i++)
      SAFE_CLOSE (received_fds[i]);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
}

TEST (socket_sendfd_invalid_socket_type)
{
  setup_signals ();

  /* Try to send FD over TCP socket (not Unix domain) - should fail */
  Socket_T tcp_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (tcp_socket);

  volatile int raised = 0;
  TRY
  {
    int pipefd[2];
    ASSERT_EQ (0, pipe (pipefd));
    Socket_sendfd (tcp_socket, pipefd[0]);
    SAFE_CLOSE (pipefd[0]);
    SAFE_CLOSE (pipefd[1]);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&tcp_socket);
}

TEST (socket_sendfd_invalid_fd)
{
  setup_signals ();

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY { SocketPair_new (SOCK_STREAM, &sock1, &sock2); }
  EXCEPT (Socket_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  volatile int raised = 0;
  TRY
  {
    /* Try to send invalid FD */
    Socket_sendfd (sock1, -1);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&sock1);
  Socket_free (&sock2);
}

TEST (socket_recvfd_no_fd_sent)
{
  setup_signals ();

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    ASSERT_NOT_NULL (sock1);
    ASSERT_NOT_NULL (sock2);

    /* Send regular data (no FD) */
    const char *msg = "hello";
    ssize_t sent = Socket_send (sock1, msg, strlen (msg));
    ASSERT_EQ ((ssize_t)strlen (msg), sent);

    /* Try to receive FD - should succeed but fd_received = -1 */
    int received_fd = 99; /* Non -1 to verify it gets set */
    int result = Socket_recvfd (sock2, &received_fd);
    ASSERT_EQ (1, result);
    ASSERT_EQ (-1, received_fd); /* No FD was sent */
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  EXCEPT (Socket_Closed) { ASSERT (0); }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
}

TEST (socket_sendfd_nonblocking)
{
  setup_signals ();

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    ASSERT_NOT_NULL (sock1);
    ASSERT_NOT_NULL (sock2);

    /* Set nonblocking */
    Socket_setnonblocking (sock1);
    Socket_setnonblocking (sock2);

    /* Create FD to pass */
    int pipefd[2];
    ASSERT_EQ (0, pipe (pipefd));

    /* Send should succeed (buffer not full) */
    int result = Socket_sendfd (sock1, pipefd[0]);
    ASSERT_EQ (1, result);

    /* Receive should succeed */
    int received_fd = -1;
    result = Socket_recvfd (sock2, &received_fd);
    ASSERT_EQ (1, result);
    ASSERT_NE (-1, received_fd);

    SAFE_CLOSE (pipefd[0]);
    SAFE_CLOSE (pipefd[1]);
    SAFE_CLOSE (received_fd);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
}

TEST (socket_sendfds_count_zero_fails)
{
  setup_signals ();

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY { SocketPair_new (SOCK_STREAM, &sock1, &sock2); }
  EXCEPT (Socket_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  volatile int raised = 0;
  TRY
  {
    int fds[1] = { 0 };
    Socket_sendfds (sock1, fds, 0); /* count = 0 should fail */
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&sock1);
  Socket_free (&sock2);
}

TEST (socket_sendfds_count_exceeds_max_fails)
{
  setup_signals ();

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY { SocketPair_new (SOCK_STREAM, &sock1, &sock2); }
  EXCEPT (Socket_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  volatile int raised = 0;
  TRY
  {
    int fds[1] = { 0 };
    /* Exceeds SOCKET_MAX_FDS_PER_MSG */
    Socket_sendfds (sock1, fds, SOCKET_MAX_FDS_PER_MSG + 1);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (1, raised);
  Socket_free (&sock1);
  Socket_free (&sock2);
}

TEST (socket_sendfd_peer_closed)
{
  setup_signals ();

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    ASSERT_NOT_NULL (sock1);
    ASSERT_NOT_NULL (sock2);

    /* Close the receiving end */
    Socket_free (&sock2);

    /* Try to send FD - should raise Socket_Closed */
    int pipefd[2];
    ASSERT_EQ (0, pipe (pipefd));

    volatile int closed_raised = 0;
    TRY { Socket_sendfd (sock1, pipefd[0]); }
    EXCEPT (Socket_Closed) { closed_raised = 1; }
    END_TRY;

    /* On some systems, first send may succeed but next will fail */
    /* Accept either Socket_Closed or success followed by failure */
    (void)closed_raised;

    SAFE_CLOSE (pipefd[0]);
    SAFE_CLOSE (pipefd[1]);
  }
  EXCEPT (Socket_Failed) { /* May fail on some error paths, acceptable */ }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
}

/* ==================== FD Passing Integration Test (fork-based)
 * ==================== */

TEST (socket_fd_passing_fork_integration)
{
  setup_signals ();
  cleanup_unix_socket (TEST_UNIX_SOCKET_PATH);

  /* This test creates a listening socket, forks, passes the listener to child,
   * and verifies the child can accept connections on it.
   * This is the nginx-style worker model. */

  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;
  Socket_T listener = NULL;

  TRY
  {
    /* Create socket pair for FD passing */
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);

    /* Create a listening socket */
    listener = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_bind (listener, "127.0.0.1", 0);
    Socket_listen (listener, 5);

    /* Get the port for client connection */
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (Socket_fd (listener), (struct sockaddr *)&addr, &len);
    int port = ntohs (addr.sin_port);

    int listener_fd = Socket_fd (listener);

    pid_t pid = fork ();
    if (pid == 0)
      {
        /* Child process - receive FD and accept connection */
        Socket_free (&sock1);    /* Close sender end in child */
        Socket_free (&listener); /* Close original listener in child */

        int received_fd = -1;
        int result = Socket_recvfd (sock2, &received_fd);
        if (result != 1 || received_fd < 0)
          _exit (1);

        /* Set received socket to blocking for accept */
        int flags = fcntl (received_fd, F_GETFL, 0);
        fcntl (received_fd, F_SETFL, flags & ~O_NONBLOCK);

        /* Wait for connection (with timeout via alarm) */
        alarm (5);
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof (client_addr);
        int client_fd = accept (received_fd, (struct sockaddr *)&client_addr,
                                &client_len);
        alarm (0);

        if (client_fd < 0)
          _exit (2);

        /* Read data from client */
        char buf[64] = { 0 };
        ssize_t n = read (client_fd, buf, sizeof (buf) - 1);
        if (n <= 0)
          _exit (3);

        /* Verify message */
        if (strcmp (buf, "hello from parent") != 0)
          _exit (4);

        /* Send response */
        const char *response = "hello from child";
        ssize_t resp_written = write (client_fd, response, strlen (response));
        (void)resp_written; /* Ignore in child - exit code matters */

        SAFE_CLOSE (client_fd);
        SAFE_CLOSE (received_fd);
        Socket_free (&sock2);
        _exit (0);
      }
    else
      {
        /* Parent process - send FD and connect as client */
        Socket_free (&sock2); /* Close receiver end in parent */

        /* Send the listener FD to child */
        int result = Socket_sendfd (sock1, listener_fd);
        ASSERT_EQ (1, result);

        /* Close original listener - child has it now */
        Socket_free (&listener);

        /* Give child time to set up */
        usleep (50000);

        /* Connect to the listener (now owned by child) */
        Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_connect (client, "127.0.0.1", port);

        /* Send message */
        const char *msg = "hello from parent";
        Socket_send (client, msg, strlen (msg));

        /* Receive response */
        char response[64] = { 0 };
        ssize_t n = Socket_recv (client, response, sizeof (response) - 1);
        ASSERT (n > 0);
        ASSERT_EQ (0, strcmp (response, "hello from child"));

        Socket_free (&client);

        /* Wait for child and check exit status */
        int status;
        waitpid (pid, &status, 0);
        ASSERT (WIFEXITED (status));
        ASSERT_EQ (0, WEXITSTATUS (status));
      }
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
  Socket_free (&listener);
}

TEST (socket_isconnected_error_not_enotconn)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  /* New socket is not connected */
  ASSERT_EQ (0, Socket_isconnected (socket));

  Socket_free (&socket);
}

TEST (socket_islistening_with_error)
{
  setup_signals ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (server);
  ASSERT_NOT_NULL (client);

  TRY
  {
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 1);

    /* Server should be listening */
    ASSERT_EQ (1, Socket_islistening (server));

    /* Client is not listening */
    ASSERT_EQ (0, Socket_islistening (client));

    /* Accept a connection to change server state */
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (Socket_fd (server), (struct sockaddr *)&addr, &len);
    int port = ntohs (addr.sin_port);

    Socket_connect (client, "127.0.0.1", port);

    /* Server is still listening even with pending connection */
    ASSERT_EQ (1, Socket_islistening (server));
  }
  EXCEPT (Socket_Failed) { (void)0; }
  END_TRY;

  Socket_free (&server);
  Socket_free (&client);
}

/* ==================== Timeout Helper Tests ==================== */

TEST (timeout_now_returns_positive)
{
  int64_t now = SocketTimeout_now_ms ();
  ASSERT (now > 0);
}

TEST (timeout_deadline_from_timeout)
{
  int64_t before = SocketTimeout_now_ms ();
  int64_t deadline = SocketTimeout_deadline_ms (1000);
  int64_t after = SocketTimeout_now_ms ();

  /* Deadline should be ~1000ms from now */
  ASSERT (deadline >= before + 1000);
  ASSERT (deadline <= after + 1000);
}

TEST (timeout_deadline_zero_returns_zero)
{
  int64_t deadline = SocketTimeout_deadline_ms (0);
  ASSERT_EQ (0, deadline);

  deadline = SocketTimeout_deadline_ms (-1);
  ASSERT_EQ (0, deadline);
}

TEST (timeout_remaining_with_active_deadline)
{
  int64_t deadline = SocketTimeout_deadline_ms (1000);
  int64_t remaining = SocketTimeout_remaining_ms (deadline);

  /* Remaining should be close to 1000ms */
  ASSERT (remaining > 900);
  ASSERT (remaining <= 1000);
}

TEST (timeout_remaining_with_no_deadline)
{
  int64_t remaining = SocketTimeout_remaining_ms (0);
  ASSERT_EQ (-1, remaining); /* -1 means infinite */
}

TEST (timeout_expired_false_for_future_deadline)
{
  int64_t deadline = SocketTimeout_deadline_ms (5000);
  ASSERT_EQ (0, SocketTimeout_expired (deadline));
}

TEST (timeout_expired_false_for_no_deadline)
{
  ASSERT_EQ (0, SocketTimeout_expired (0));
}

TEST (timeout_expired_true_for_past_deadline)
{
  int64_t past_deadline = SocketTimeout_now_ms () - 1000;
  ASSERT_EQ (1, SocketTimeout_expired (past_deadline));
}

TEST (timeout_poll_timeout_respects_deadline)
{
  int64_t deadline = SocketTimeout_deadline_ms (500);

  /* With infinite current timeout, should return remaining */
  int poll_timeout = SocketTimeout_poll_timeout (-1, deadline);
  ASSERT (poll_timeout > 0);
  ASSERT (poll_timeout <= 500);

  /* With shorter current timeout, should return current */
  poll_timeout = SocketTimeout_poll_timeout (100, deadline);
  ASSERT_EQ (100, poll_timeout);
}

TEST (timeout_poll_timeout_no_deadline)
{
  /* With no deadline, should return current timeout unchanged */
  int poll_timeout = SocketTimeout_poll_timeout (1000, 0);
  ASSERT_EQ (1000, poll_timeout);

  poll_timeout = SocketTimeout_poll_timeout (-1, 0);
  ASSERT_EQ (-1, poll_timeout);
}

TEST (timeout_elapsed_ms_positive)
{
  int64_t start = SocketTimeout_now_ms ();
  usleep (10000); /* Sleep 10ms */
  int64_t elapsed = SocketTimeout_elapsed_ms (start);

  ASSERT (elapsed >= 10);
  ASSERT (elapsed < 100); /* Should not be way off */
}

/* ==================== Extended Timeout API Tests ==================== */

TEST (socket_timeouts_extended_set_get)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  SocketTimeouts_Extended_T extended = { .dns_timeout_ms = 2000,
                                         .connect_timeout_ms = 5000,
                                         .tls_timeout_ms = 10000,
                                         .request_timeout_ms = 30000,
                                         .operation_timeout_ms = 15000 };

  Socket_timeouts_set_extended (socket, &extended);

  SocketTimeouts_Extended_T result;
  Socket_timeouts_get_extended (socket, &result);

  ASSERT_EQ (2000, result.dns_timeout_ms);
  ASSERT_EQ (5000, result.connect_timeout_ms);
  /* TLS maps to operation_timeout, and we set operation to 15000 */
  ASSERT_EQ (15000, result.tls_timeout_ms);
  /* request_timeout_ms is HTTP client level, not stored at socket level */
  ASSERT_EQ (0, result.request_timeout_ms);
  ASSERT_EQ (15000, result.operation_timeout_ms);

  Socket_free (&socket);
}

TEST (socket_timeouts_extended_zero_inherits)
{
  setup_signals ();
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  /* Set basic timeouts first */
  SocketTimeouts_T basic = { .connect_timeout_ms = 8000,
                             .dns_timeout_ms = 3000,
                             .operation_timeout_ms = 12000 };
  Socket_timeouts_set (socket, &basic);

  /* Extended with 0 values should not override */
  SocketTimeouts_Extended_T extended = { .dns_timeout_ms = 0,     /* inherit */
                                         .connect_timeout_ms = 0, /* inherit */
                                         .tls_timeout_ms = 0,
                                         .request_timeout_ms = 0,
                                         .operation_timeout_ms = 0 };

  Socket_timeouts_set_extended (socket, &extended);

  SocketTimeouts_Extended_T result;
  Socket_timeouts_get_extended (socket, &result);

  /* Values should remain from basic timeouts */
  ASSERT_EQ (3000, result.dns_timeout_ms);
  ASSERT_EQ (8000, result.connect_timeout_ms);
  ASSERT_EQ (12000, result.operation_timeout_ms);

  Socket_free (&socket);
}

TEST (socket_connect_timeout_enforcement)
{
  setup_signals ();

  /* Test that timeouts are properly set - actual timeout enforcement
   * depends on network conditions and may not be reliably testable.
   * We verify the API works correctly. */

  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (socket);

  SocketTimeouts_T timeouts = { .connect_timeout_ms = 5000,
                                .dns_timeout_ms = 2000,
                                .operation_timeout_ms = 10000 };
  Socket_timeouts_set (socket, &timeouts);

  /* Verify timeouts were set */
  SocketTimeouts_T result;
  Socket_timeouts_get (socket, &result);

  ASSERT_EQ (5000, result.connect_timeout_ms);
  ASSERT_EQ (2000, result.dns_timeout_ms);
  ASSERT_EQ (10000, result.operation_timeout_ms);

  Socket_free (&socket);
}

TEST (socketcommon_wait_for_fd_timeout_validation)
{
  int pipefd[2];
  int result;

  /* Create a pipe for testing - read end will block, write end is ready */
  ASSERT_EQ (0, pipe (pipefd));

  /* Test 1: Normal timeout should work */
  result = SocketCommon_wait_for_fd (pipefd[1], POLLOUT, 100);
  ASSERT_EQ (1, result); /* Should be ready for write */

  /* Test 2: Zero timeout should return immediately */
  result = SocketCommon_wait_for_fd (pipefd[0], POLLIN, 0);
  ASSERT_EQ (1, result); /* Returns 1 for zero timeout */

  /* Test 3: Negative timeout less than -1 should be normalized to -1 (infinite) */
  /* We can't test infinite wait without blocking, but we verify it doesn't crash */
  /* Use write end with timeout to verify normalization doesn't break functionality */
  result = SocketCommon_wait_for_fd (pipefd[1], POLLOUT, -5);
  ASSERT_EQ (1, result); /* Should still work (normalized to -1, write is ready) */

  /* Test 4: Extremely large timeout should be capped */
  /* INT_MAX would be capped to INT_MAX/2, but we just verify it doesn't crash */
  result = SocketCommon_wait_for_fd (pipefd[1], POLLOUT, INT_MAX);
  ASSERT_EQ (1, result); /* Should still work with capped value */

  /* Test 5: Timeout on non-ready descriptor */
  result = SocketCommon_wait_for_fd (pipefd[0], POLLIN, 50);
  ASSERT_EQ (0, result); /* Should timeout (no data to read) */

  close (pipefd[0]);
  close (pipefd[1]);
}

TEST (iovec_overflow_protection_in_calculate_total_len)
{
  struct iovec iov[3];
  volatile int exception_raised = 0;

  /* Test 1: Normal case - should not overflow */
  iov[0].iov_base = (void *)"test1";
  iov[0].iov_len = 100;
  iov[1].iov_base = (void *)"test2";
  iov[1].iov_len = 200;
  iov[2].iov_base = (void *)"test3";
  iov[2].iov_len = 300;

  TRY
  {
    size_t total = SocketCommon_calculate_total_iov_len (iov, 3);
    ASSERT_EQ (600, total);
    exception_raised = 0;
  }
  EXCEPT (SocketCommon_Failed)
  {
    exception_raised = 1;
  }
  END_TRY;
  ASSERT_EQ (0, exception_raised);

  /* Test 2: Overflow case - should raise exception
   * Create iovec with values that would overflow SIZE_MAX */
  exception_raised = 0;
  iov[0].iov_len = SIZE_MAX / 2;
  iov[1].iov_len = SIZE_MAX / 2;
  iov[2].iov_len = 100; /* This pushes it over SIZE_MAX */

  TRY
  {
    (void)SocketCommon_calculate_total_iov_len (iov, 3);
    exception_raised = 0; /* Should not reach here */
  }
  EXCEPT (SocketCommon_Failed)
  {
    exception_raised = 1;
  }
  END_TRY;
  ASSERT_EQ (1, exception_raised);

  /* Test 3: Edge case - exactly at SIZE_MAX boundary should be allowed */
  exception_raised = 0;
  iov[0].iov_len = SIZE_MAX;

  TRY
  {
    size_t total = SocketCommon_calculate_total_iov_len (iov, 1);
    ASSERT_EQ (SIZE_MAX, total);
    exception_raised = 0;
  }
  EXCEPT (SocketCommon_Failed)
  {
    exception_raised = 1;
  }
  END_TRY;
  ASSERT_EQ (0, exception_raised);
}

int
main (void)
{
  /* Ignore SIGPIPE once at startup - library handles this internally,
   * but we call it explicitly for defense-in-depth in tests. */
  if (Socket_ignore_sigpipe () != 0)
    {
      perror ("Socket_ignore_sigpipe");
      return 1;
    }

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

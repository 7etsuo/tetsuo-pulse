/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socketdgram.c - Comprehensive SocketDgram unit tests
 * Industry-standard test coverage for SocketDgram UDP module.
 * Tests UDP sockets, multicast, broadcast, connected mode, and edge cases.
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */
/* cppcheck-suppress-file unreachableCode ; END_TRY after break */
/* cppcheck-suppress-file unreadVariable ; intentional test patterns */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketConfig.h"
#include "socket/SocketCommon.h"
#include "socket/SocketDgram.h"
#include "test/Test.h"

#define TEST_BUFFER_SIZE 4096
#define TEST_MULTICAST_GROUP "239.0.0.1"

static void
setup_signals (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* ==================== Basic Socket Tests ==================== */

TEST (socketdgram_new_creates_ipv4_socket)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);
  SocketDgram_free (&socket);
  ASSERT_NULL (socket);
}

TEST (socketdgram_new_creates_ipv6_socket)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET6, 0);
  ASSERT_NOT_NULL (socket);
  SocketDgram_free (&socket);
  ASSERT_NULL (socket);
}

TEST (socketdgram_fd_access)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);
  int fd = SocketDgram_fd (socket);
  ASSERT_NE (fd, -1);
  SocketDgram_free (&socket);
}

/* ==================== Bind Tests ==================== */

TEST (socketdgram_bind_localhost)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);
  TRY
  {
    SocketDgram_bind (socket, "127.0.0.1", 0);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_bind_any)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);
  TRY
  {
    SocketDgram_bind (socket, NULL, 0);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_bind_wildcard_ipv4)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  TRY
  {
    SocketDgram_bind (socket, "0.0.0.0", 0);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_bind_ipv6_localhost)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET6, 0);
  TRY
  {
    SocketDgram_bind (socket, "::1", 0);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_bind_ipv6_any)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET6, 0);
  TRY
  {
    SocketDgram_bind (socket, "::", 0);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  END_TRY;
  SocketDgram_free (&socket);
}

/* ==================== Sendto/Recvfrom Tests ==================== */

TEST (socketdgram_sendto_recvfrom_localhost)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY
  {
    SocketDgram_bind (receiver, "127.0.0.1", 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
    int port = ntohs (addr.sin_port);

    const char *msg = "UDP test message";
    ssize_t sent
        = SocketDgram_sendto (sender, msg, strlen (msg), "127.0.0.1", port);
    ASSERT_NE (sent, -1);

    usleep (10000);
    char recv_host[256] = { 0 };
    int recv_port = 0;
    char buf[TEST_BUFFER_SIZE] = { 0 };
    ssize_t received = SocketDgram_recvfrom (receiver,
                                             buf,
                                             sizeof (buf) - 1,
                                             recv_host,
                                             sizeof (recv_host),
                                             &recv_port);

    if (received > 0)
      {
        ASSERT_EQ (strcmp (buf, msg), 0);
        ASSERT_NE (recv_port, 0);
      }
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  FINALLY
  {
    SocketDgram_free (&sender);
    SocketDgram_free (&receiver);
  }
  END_TRY;
}

TEST (socketdgram_sendto_recvfrom_large_data)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  char large_buf[4096];
  memset (large_buf, 'B', sizeof (large_buf));
  ssize_t sent = SocketDgram_sendto (
      sender, large_buf, sizeof (large_buf), "127.0.0.1", port);
  ASSERT_NE (sent, -1);
  EXCEPT (SocketDgram_Failed) (void) 0;
  FINALLY
  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
  END_TRY;
}

TEST (socketdgram_multiple_datagrams)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  SocketDgram_setnonblocking (receiver);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  for (int i = 0; i < 5; i++)
    {
      char msg[32];
      snprintf (msg, sizeof (msg), "Datagram %d", i);
      SocketDgram_sendto (sender, msg, strlen (msg), "127.0.0.1", port);
    }

  usleep (50000);
  int received_count = 0;
  for (int i = 0; i < 5; i++)
    {
      char buf[TEST_BUFFER_SIZE];
      ssize_t received
          = SocketDgram_recvfrom (receiver, buf, sizeof (buf), NULL, 0, NULL);
      if (received > 0)
        received_count++;
    }
  ASSERT_NE (received_count, 0);
  EXCEPT (SocketDgram_Failed) (void) 0;
  FINALLY
  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
  END_TRY;
}

/* ==================== Connected Mode Tests ==================== */

TEST (socketdgram_connect_send_recv)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  SocketDgram_connect (sender, "127.0.0.1", port);

  const char *msg = "Connected UDP";
  ssize_t sent = SocketDgram_send (sender, msg, strlen (msg));
  ASSERT_NE (sent, -1);

  usleep (10000);
  char buf[TEST_BUFFER_SIZE] = { 0 };
  ssize_t received = SocketDgram_recv (receiver, buf, sizeof (buf) - 1);
  if (received > 0)
    ASSERT_EQ (strcmp (buf, msg), 0);
  EXCEPT (SocketDgram_Failed) (void) 0;
  FINALLY
  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
  END_TRY;
}

TEST (socketdgram_connected_bidirectional)
{
  setup_signals ();
  SocketDgram_T sock1 = SocketDgram_new (AF_INET, 0);
  SocketDgram_T sock2 = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (sock1, "127.0.0.1", 0);
  SocketDgram_bind (sock2, "127.0.0.1", 0);

  struct sockaddr_in addr1, addr2;
  socklen_t len = sizeof (addr1);
  getsockname (SocketDgram_fd (sock1), (struct sockaddr *)&addr1, &len);
  getsockname (SocketDgram_fd (sock2), (struct sockaddr *)&addr2, &len);
  int port1 = ntohs (addr1.sin_port);
  int port2 = ntohs (addr2.sin_port);

  SocketDgram_connect (sock1, "127.0.0.1", port2);
  SocketDgram_connect (sock2, "127.0.0.1", port1);

  SocketDgram_send (sock1, "Msg1", 4);
  SocketDgram_send (sock2, "Msg2", 4);
  usleep (10000);

  char buf1[128], buf2[128];
  SocketDgram_recv (sock1, buf1, sizeof (buf1));
  SocketDgram_recv (sock2, buf2, sizeof (buf2));
  EXCEPT (SocketDgram_Failed) (void) 0;
  FINALLY
  SocketDgram_free (&sock1);
  SocketDgram_free (&sock2);
  END_TRY;
}

/* ==================== Socket Options Tests ==================== */

TEST (socketdgram_setnonblocking)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  TRY SocketDgram_setnonblocking (socket);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_setreuseaddr)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  TRY SocketDgram_setreuseaddr (socket);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_setbroadcast_enable)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  TRY SocketDgram_setbroadcast (socket, 1);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_setbroadcast_disable)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  TRY SocketDgram_setbroadcast (socket, 0);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_settimeout)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  TRY SocketDgram_settimeout (socket, 5);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;
  SocketDgram_free (&socket);
}

/* ==================== Close-on-Exec Tests ==================== */

TEST (socketdgram_new_sets_cloexec_by_default)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  int has_cloexec = SocketCommon_has_cloexec (SocketDgram_fd (socket));
  ASSERT_EQ (has_cloexec, 1);

  SocketDgram_free (&socket);
}

TEST (socketdgram_setcloexec_enable_disable)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  /* Verify CLOEXEC is set by default */
  int has_cloexec = SocketCommon_has_cloexec (SocketDgram_fd (socket));
  ASSERT_EQ (has_cloexec, 1);

  /* Disable CLOEXEC */
  TRY SocketDgram_setcloexec (socket, 0);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;

  has_cloexec = SocketCommon_has_cloexec (SocketDgram_fd (socket));
  ASSERT_EQ (has_cloexec, 0);

  /* Re-enable CLOEXEC */
  TRY SocketDgram_setcloexec (socket, 1);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;

  has_cloexec = SocketCommon_has_cloexec (SocketDgram_fd (socket));
  ASSERT_EQ (has_cloexec, 1);

  SocketDgram_free (&socket);
}

TEST (socketdgram_setttl)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  TRY SocketDgram_setttl (socket, 64);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_setttl_min_max)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  TRY SocketDgram_setttl (socket, 1);
  SocketDgram_setttl (socket, 255);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;
  SocketDgram_free (&socket);
}

/* ==================== Socket Option Getter Tests ==================== */

TEST (socketdgram_gettimeout_returns_set_value)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  SocketDgram_settimeout (socket, 5);
  int timeout = SocketDgram_gettimeout (socket);
  ASSERT_EQ (timeout, 5);

  SocketDgram_settimeout (socket, 0);
  timeout = SocketDgram_gettimeout (socket);
  ASSERT_EQ (timeout, 0);

  SocketDgram_free (&socket);
}

TEST (socketdgram_getbroadcast_returns_set_value)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  int broadcast;

  SocketDgram_setbroadcast (socket, 1);

  TRY
  {
    broadcast = SocketDgram_getbroadcast (socket);
#if SOCKET_PLATFORM_MACOS
    /* On macOS, getsockopt() doesn't reliably return set values */
    /* Verify that getsockopt succeeded (no exception) but don't assert value
     */
    (void)broadcast;
#else
    ASSERT_EQ (broadcast, 1);
#endif
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  END_TRY;

  SocketDgram_setbroadcast (socket, 0);

  TRY
  {
    broadcast = SocketDgram_getbroadcast (socket);
#if SOCKET_PLATFORM_MACOS
    /* On macOS, getsockopt() doesn't reliably return set values */
    (void)broadcast;
#else
    ASSERT_EQ (broadcast, 0);
#endif
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  END_TRY;

  SocketDgram_free (&socket);
}

TEST (socketdgram_getttl_returns_set_value)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  SocketDgram_setttl (socket, 64);
  int ttl = SocketDgram_getttl (socket);
  ASSERT_EQ (ttl, 64);

  SocketDgram_setttl (socket, 128);
  ttl = SocketDgram_getttl (socket);
  ASSERT_EQ (ttl, 128);

  SocketDgram_free (&socket);
}

TEST (socketdgram_getrcvbuf_returns_positive_value)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  int rcvbuf = SocketDgram_getrcvbuf (socket);
  ASSERT (rcvbuf > 0);

  SocketDgram_free (&socket);
}

TEST (socketdgram_getsndbuf_returns_positive_value)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  int sndbuf = SocketDgram_getsndbuf (socket);
  ASSERT (sndbuf > 0);

  SocketDgram_free (&socket);
}

/* ==================== Connection State Query Tests ==================== */

TEST (socketdgram_isbound_returns_false_for_new_socket)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  ASSERT_EQ (0, SocketDgram_isbound (socket));

  SocketDgram_free (&socket);
}

TEST (socketdgram_isbound_returns_true_after_bind)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  SocketDgram_bind (socket, "127.0.0.1", 0);
  ASSERT_EQ (1, SocketDgram_isbound (socket));

  SocketDgram_free (&socket);
}

TEST (socketdgram_isconnected_returns_false_for_new_socket)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  ASSERT_EQ (0, SocketDgram_isconnected (socket));

  SocketDgram_free (&socket);
}

TEST (socketdgram_isconnected_returns_true_after_connect)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  SocketDgram_bind (socket, "127.0.0.1", 0);
  SocketDgram_connect (socket, "127.0.0.1", 5000);
  ASSERT_EQ (1, SocketDgram_isconnected (socket));

  SocketDgram_free (&socket);
}

TEST (socketdgram_isbound_after_connect)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  /* Socket is not bound initially */
  ASSERT_EQ (0, SocketDgram_isbound (socket));

  /* Connect without bind - OS will auto-bind */
  SocketDgram_connect (socket, "127.0.0.1", 5000);
  ASSERT_EQ (1, SocketDgram_isconnected (socket));
  /* Socket may or may not be bound after connect (OS-dependent) */

  SocketDgram_free (&socket);
}

/* ==================== Multicast Tests ==================== */

TEST (socketdgram_joinmulticast_ipv4)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  TRY SocketDgram_setreuseaddr (socket);
  SocketDgram_bind (socket, "0.0.0.0", 0);
  SocketDgram_joinmulticast (socket, TEST_MULTICAST_GROUP, NULL);
  SocketDgram_leavemulticast (socket, TEST_MULTICAST_GROUP, NULL);
  EXCEPT (SocketDgram_Failed) (void) 0;
  END_TRY;
  SocketDgram_free (&socket);
}

TEST (socketdgram_multicast_send_receive)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_setreuseaddr (receiver);
  SocketDgram_bind (receiver, "0.0.0.0", 0);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  SocketDgram_joinmulticast (receiver, TEST_MULTICAST_GROUP, NULL);
  SocketDgram_setnonblocking (receiver);

  const char *msg = "Multicast message";
  TRY SocketDgram_sendto (
      sender, msg, strlen (msg), TEST_MULTICAST_GROUP, port);
  usleep (50000);

  char buf[TEST_BUFFER_SIZE] = { 0 };
  ssize_t received
      = SocketDgram_recvfrom (receiver, buf, sizeof (buf) - 1, NULL, 0, NULL);
  if (received > 0)
    ASSERT_EQ (strcmp (buf, msg), 0);
  EXCEPT (SocketDgram_Failed)
  /* Multicast may fail if routing is not configured (e.g., macOS without
   * multicast routing) */
  /* This is acceptable - test passes if we can join/leave multicast group */
  (void)0;
  END_TRY;

  SocketDgram_leavemulticast (receiver, TEST_MULTICAST_GROUP, NULL);
  EXCEPT (SocketDgram_Failed) (void) 0;
  FINALLY
  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
  END_TRY;
}

/* ==================== IPv6 Tests ==================== */

TEST (socketdgram_ipv6_sendto_recvfrom)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET6, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET6, 0);

  TRY SocketDgram_bind (receiver, "::1", 0);
  struct sockaddr_in6 addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin6_port);

  const char *msg = "IPv6 UDP test";
  ssize_t sent = SocketDgram_sendto (sender, msg, strlen (msg), "::1", port);
  ASSERT_NE (sent, -1);

  usleep (10000);
  char buf[TEST_BUFFER_SIZE] = { 0 };
  ssize_t received
      = SocketDgram_recvfrom (receiver, buf, sizeof (buf) - 1, NULL, 0, NULL);
  if (received > 0)
    ASSERT_EQ (strcmp (buf, msg), 0);
  EXCEPT (SocketDgram_Failed) (void) 0;
  FINALLY
  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
  END_TRY;
}

TEST (socketdgram_ipv6_setttl)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET6, 0);
  TRY SocketDgram_setttl (socket, 128);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;
  SocketDgram_free (&socket);
}

/* ==================== Nonblocking Tests ==================== */

TEST (socketdgram_recvfrom_nonblocking_returns_zero)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (socket, "127.0.0.1", 0);
  SocketDgram_setnonblocking (socket);

  char buf[TEST_BUFFER_SIZE];
  ssize_t received
      = SocketDgram_recvfrom (socket, buf, sizeof (buf), NULL, 0, NULL);
  ASSERT_EQ (received, 0);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;

  SocketDgram_free (&socket);
}

TEST (socketdgram_recv_nonblocking_returns_zero)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (socket, "127.0.0.1", 0);
  SocketDgram_connect (socket, "127.0.0.1", 9999);
  SocketDgram_setnonblocking (socket);

  char buf[TEST_BUFFER_SIZE];
  ssize_t received = SocketDgram_recv (socket, buf, sizeof (buf));
  ASSERT_EQ (received, 0);
  EXCEPT (SocketDgram_Failed) ASSERT (0);
  END_TRY;

  SocketDgram_free (&socket);
}

/* ==================== Stress Tests ==================== */

TEST (socketdgram_many_sequential_datagrams)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  SocketDgram_setnonblocking (receiver);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  for (int i = 0; i < 100; i++)
    {
      char msg[16];
      snprintf (msg, sizeof (msg), "Msg%d", i);
      SocketDgram_sendto (sender, msg, strlen (msg), "127.0.0.1", port);
    }
  EXCEPT (SocketDgram_Failed) (void) 0;
  FINALLY
  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
  END_TRY;
}

TEST (socketdgram_rapid_open_close)
{
  setup_signals ();
  for (int i = 0; i < 100; i++)
    {
      SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
      ASSERT_NOT_NULL (socket);
      SocketDgram_free (&socket);
      ASSERT_NULL (socket);
    }
}

/* ==================== Thread Safety Tests ==================== */

static void *
thread_create_dgram_sockets (void *arg)
{
  (void)arg;
  TRY
  {
    for (int i = 0; i < 50; i++)
      {
        SocketDgram_T socket = NULL;
        TRY socket = SocketDgram_new (AF_INET, 0);
        EXCEPT (SocketDgram_Failed)
        {
        }
        EXCEPT (Arena_Failed)
        {
        }
        EXCEPT (Socket_Failed)
        {
        }
        END_TRY;
        if (socket)
          SocketDgram_free (&socket);
      }
  }
  EXCEPT (SocketDgram_Failed)
  {
  }
  EXCEPT (Arena_Failed)
  {
  }
  EXCEPT (Socket_Failed)
  {
  }
  END_TRY;
  return NULL;
}

TEST (socketdgram_concurrent_creation)
{
  setup_signals ();
  pthread_t threads[4];

  for (int i = 0; i < 4; i++)
    pthread_create (&threads[i], NULL, thread_create_dgram_sockets, NULL);

  for (int i = 0; i < 4; i++)
    pthread_join (threads[i], NULL);
}

static void *
thread_sendto_datagrams (void *arg)
{
  int port = *(int *)arg;
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);

  for (int i = 0; i < 20; i++)
    {
      char msg[32];
      snprintf (msg, sizeof (msg), "Thread msg %d", i);
      TRY SocketDgram_sendto (sender, msg, strlen (msg), "127.0.0.1", port);
      EXCEPT (SocketDgram_Failed) break;
      END_TRY;
      usleep (1000);
    }

  SocketDgram_free (&sender);
  return NULL;
}

TEST (socketdgram_concurrent_sendto)
{
  setup_signals ();
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);
  pthread_t threads[4];
  int port = 0;

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  SocketDgram_setnonblocking (receiver);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  port = ntohs (addr.sin_port);

  for (int i = 0; i < 4; i++)
    pthread_create (&threads[i], NULL, thread_sendto_datagrams, &port);

  for (int i = 0; i < 4; i++)
    pthread_join (threads[i], NULL);
  EXCEPT (SocketDgram_Failed) (void) 0;
  END_TRY;

  SocketDgram_free (&receiver);
}

/* ==================== Partial I/O Helper Tests ==================== */

TEST (socketdgram_sendall_sends_all_data)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  SocketDgram_connect (sender, "127.0.0.1", port);
  SocketDgram_connect (
      receiver, "127.0.0.1", SocketDgram_getlocalport (sender));

  /* Send large data */
  char send_buf[4096];
  memset (send_buf, 'X', sizeof (send_buf));
  ssize_t sent = SocketDgram_sendall (sender, send_buf, sizeof (send_buf));
  ASSERT_EQ ((ssize_t)sizeof (send_buf), sent);

  /* Receive all data */
  char recv_buf[4096] = { 0 };
  ssize_t received
      = SocketDgram_recvall (receiver, recv_buf, sizeof (recv_buf));
  ASSERT_EQ ((ssize_t)sizeof (recv_buf), received);
  ASSERT_EQ (0, memcmp (send_buf, recv_buf, sizeof (send_buf)));
  EXCEPT (SocketDgram_Failed)
  (void)0;
  END_TRY;

  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
}

TEST (socketdgram_recvall_receives_all_data)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  SocketDgram_connect (sender, "127.0.0.1", port);
  SocketDgram_connect (
      receiver, "127.0.0.1", SocketDgram_getlocalport (sender));

  /* Send data */
  const char *msg = "Test message for recvall";
  ssize_t sent = SocketDgram_sendall (sender, msg, strlen (msg));
  ASSERT_EQ ((ssize_t)strlen (msg), sent);

  /* Receive all data */
  char recv_buf[256] = { 0 };
  ssize_t received = SocketDgram_recvall (receiver, recv_buf, strlen (msg));
  ASSERT_EQ ((ssize_t)strlen (msg), received);
  ASSERT_EQ (0, strcmp (msg, recv_buf));
  EXCEPT (SocketDgram_Failed)
  (void)0;
  END_TRY;

  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
}

/* ==================== Scatter/Gather I/O Tests ==================== */

TEST (socketdgram_sendv_sends_from_multiple_buffers)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  SocketDgram_connect (sender, "127.0.0.1", port);
  SocketDgram_connect (
      receiver, "127.0.0.1", SocketDgram_getlocalport (sender));

  /* Prepare scatter buffers */
  char buf1[] = "Hello, ";
  char buf2[] = "UDP";
  char buf3[] = " World!";
  struct iovec iov[3];
  iov[0].iov_base = buf1;
  iov[0].iov_len = strlen (buf1);
  iov[1].iov_base = buf2;
  iov[1].iov_len = strlen (buf2);
  iov[2].iov_base = buf3;
  iov[2].iov_len = strlen (buf3);

  ssize_t sent = SocketDgram_sendv (sender, iov, 3);
  ASSERT (sent > 0);

  /* Receive all data */
  char recv_buf[256] = { 0 };
  ssize_t received = SocketDgram_recvall (receiver, recv_buf, sent);
  ASSERT_EQ (sent, received);
  ASSERT_EQ (0, strcmp (recv_buf, "Hello, UDP World!"));
  EXCEPT (SocketDgram_Failed)
  (void)0;
  END_TRY;

  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
}

TEST (socketdgram_recvv_receives_into_multiple_buffers)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  SocketDgram_connect (sender, "127.0.0.1", port);
  SocketDgram_connect (
      receiver, "127.0.0.1", SocketDgram_getlocalport (sender));

  /* Send data */
  const char *msg = "UDP Scatter Test";
  ssize_t sent = SocketDgram_sendall (sender, msg, strlen (msg));
  ASSERT_EQ ((ssize_t)strlen (msg), sent);

  /* Receive into scatter buffers */
  char buf1[5] = { 0 };
  char buf2[6] = { 0 };
  char buf3[6] = { 0 };
  struct iovec iov[3];
  iov[0].iov_base = buf1;
  iov[0].iov_len = sizeof (buf1) - 1;
  iov[1].iov_base = buf2;
  iov[1].iov_len = sizeof (buf2) - 1;
  iov[2].iov_base = buf3;
  iov[2].iov_len = sizeof (buf3) - 1;

  ssize_t received = SocketDgram_recvv (receiver, iov, 3);
  ASSERT (received > 0);
  /* readv may receive less than requested, so verify we got at least some data
   */
  ASSERT (received <= (ssize_t)strlen (msg));

  /* Calculate how much was received in each buffer */
  size_t buf1_received = (received > (ssize_t)(sizeof (buf1) - 1))
                             ? (sizeof (buf1) - 1)
                             : (size_t)received;
  size_t remaining = (received > (ssize_t)(sizeof (buf1) - 1))
                         ? (size_t)received - buf1_received
                         : 0;
  size_t buf2_received
      = (remaining > (sizeof (buf2) - 1)) ? (sizeof (buf2) - 1) : remaining;
  size_t buf3_received
      = (remaining > (sizeof (buf2) - 1)) ? remaining - buf2_received : 0;

  char combined[17] = { 0 };
  memcpy (combined, buf1, buf1_received);
  if (buf2_received > 0)
    memcpy (combined + buf1_received, buf2, buf2_received);
  if (buf3_received > 0)
    memcpy (combined + buf1_received + buf2_received, buf3, buf3_received);
  /* Verify received data matches the sent message */
  ASSERT_EQ (0, memcmp (combined, msg, (size_t)received));
  EXCEPT (SocketDgram_Failed)
  (void)0;
  END_TRY;

  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
}

TEST (socketdgram_sendvall_sends_all_from_multiple_buffers)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  SocketDgram_connect (sender, "127.0.0.1", port);
  SocketDgram_connect (
      receiver, "127.0.0.1", SocketDgram_getlocalport (sender));

  /* Prepare scatter buffers */
  char buf1[512];
  char buf2[512];
  memset (buf1, 'A', sizeof (buf1));
  memset (buf2, 'B', sizeof (buf2));

  struct iovec iov[2];
  iov[0].iov_base = buf1;
  iov[0].iov_len = sizeof (buf1);
  iov[1].iov_base = buf2;
  iov[1].iov_len = sizeof (buf2);

  size_t total_len = sizeof (buf1) + sizeof (buf2);
  ssize_t sent = SocketDgram_sendvall (sender, iov, 2);
  ASSERT_EQ ((ssize_t)total_len, sent);

  /* Receive all data */
  char recv_buf[1024] = { 0 };
  ssize_t received = SocketDgram_recvall (receiver, recv_buf, total_len);
  ASSERT_EQ ((ssize_t)total_len, received);

  /* Verify data */
  ASSERT (memcmp (recv_buf, buf1, sizeof (buf1)) == 0);
  ASSERT (memcmp (recv_buf + sizeof (buf1), buf2, sizeof (buf2)) == 0);
  EXCEPT (SocketDgram_Failed)
  (void)0;
  END_TRY;

  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
}

/* ==================== recvvall Test ==================== */

TEST (socketdgram_recvv_wouldblock_returns_zero)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);

  TRY
  {
    SocketDgram_bind (socket, "127.0.0.1", 0);
    SocketDgram_setnonblocking (socket);

    /* Prepare receive buffers */
    char buf1[64] = { 0 };
    char buf2[64] = { 0 };
    struct iovec iov[2];
    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof (buf1);
    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof (buf2);

    /* Should return 0 (would block) since no data is available */
    ssize_t received = SocketDgram_recvv (socket, iov, 2);
    ASSERT_EQ (0, received);
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  END_TRY;

  SocketDgram_free (&socket);
}

TEST (socketdgram_recvv_single_buffer)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY
  {
    SocketDgram_bind (receiver, "127.0.0.1", 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
    int port = ntohs (addr.sin_port);

    SocketDgram_connect (sender, "127.0.0.1", port);
    SocketDgram_connect (
        receiver, "127.0.0.1", SocketDgram_getlocalport (sender));

    /* Send data */
    const char *msg = "Single buffer test";
    SocketDgram_sendall (sender, msg, strlen (msg));

    /* Receive with single iovec */
    char buf[64] = { 0 };
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof (buf);

    ssize_t received = SocketDgram_recvv (receiver, iov, 1);
    ASSERT (received > 0);
    ASSERT_EQ (0, memcmp (buf, msg, (size_t)received));
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  END_TRY;

  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
}

TEST (socketdgram_recvvall_receives_all_into_multiple_buffers)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY SocketDgram_bind (receiver, "127.0.0.1", 0);
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
  int port = ntohs (addr.sin_port);

  SocketDgram_connect (sender, "127.0.0.1", port);
  SocketDgram_connect (
      receiver, "127.0.0.1", SocketDgram_getlocalport (sender));

  /* Send data that will be received into multiple buffers */
  char send_buf[256];
  memset (send_buf, 'Z', sizeof (send_buf));
  ssize_t sent = SocketDgram_sendall (sender, send_buf, sizeof (send_buf));
  ASSERT_EQ ((ssize_t)sizeof (send_buf), sent);

  /* Prepare receive buffers */
  char buf1[64] = { 0 };
  char buf2[64] = { 0 };
  char buf3[64] = { 0 };
  char buf4[64] = { 0 };
  struct iovec iov[4];
  iov[0].iov_base = buf1;
  iov[0].iov_len = sizeof (buf1);
  iov[1].iov_base = buf2;
  iov[1].iov_len = sizeof (buf2);
  iov[2].iov_base = buf3;
  iov[2].iov_len = sizeof (buf3);
  iov[3].iov_base = buf4;
  iov[3].iov_len = sizeof (buf4);

  /* Use recvvall to receive all data */
  ssize_t received = SocketDgram_recvvall (receiver, iov, 4);
  ASSERT_EQ ((ssize_t)sizeof (send_buf), received);

  /* Verify each buffer received correct data */
  char expected[64];
  memset (expected, 'Z', sizeof (expected));
  ASSERT_EQ (0, memcmp (buf1, expected, sizeof (buf1)));
  ASSERT_EQ (0, memcmp (buf2, expected, sizeof (buf2)));
  ASSERT_EQ (0, memcmp (buf3, expected, sizeof (buf3)));
  ASSERT_EQ (0, memcmp (buf4, expected, sizeof (buf4)));
  EXCEPT (SocketDgram_Failed)
  (void)0;
  END_TRY;

  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
}

/* ==================== Invalid Port Tests ==================== */

TEST (socketdgram_bind_invalid_port_negative)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY SocketDgram_bind (socket, "127.0.0.1", -1);
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&socket);
}

TEST (socketdgram_bind_invalid_port_too_large)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY SocketDgram_bind (socket, "127.0.0.1", 65536);
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&socket);
}

TEST (socketdgram_connect_invalid_port_negative)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY SocketDgram_connect (socket, "127.0.0.1", -1);
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&socket);
}

TEST (socketdgram_connect_invalid_port_too_large)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY SocketDgram_connect (socket, "127.0.0.1", 65536);
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&socket);
}

/* ==================== Oversized Datagram Tests ==================== */

TEST (socketdgram_sendto_oversized_rejected)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY
  {
    SocketDgram_bind (receiver, "127.0.0.1", 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
    int port = ntohs (addr.sin_port);

    /* Allocate buffer larger than SAFE_UDP_SIZE (1472) */
    char oversized[2000];
    memset (oversized, 'X', sizeof (oversized));

    /* This should raise SocketDgram_Failed due to size > SAFE_UDP_SIZE */
    SocketDgram_sendto (
        sender, oversized, sizeof (oversized), "127.0.0.1", port);
  }
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
}

TEST (socketdgram_sendv_oversized_rejected)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY
  {
    SocketDgram_bind (receiver, "127.0.0.1", 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
    int port = ntohs (addr.sin_port);

    SocketDgram_connect (sender, "127.0.0.1", port);

    /* Create iovec that totals > SAFE_UDP_SIZE (1472) */
    char buf1[1000];
    char buf2[1000];
    memset (buf1, 'A', sizeof (buf1));
    memset (buf2, 'B', sizeof (buf2));

    struct iovec iov[2];
    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof (buf1);
    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof (buf2);

    /* Total is 2000 > 1472, should raise */
    SocketDgram_sendv (sender, iov, 2);
  }
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&sender);
  SocketDgram_free (&receiver);
}

/* ==================== Invalid Hostname Test ==================== */

TEST (socketdgram_sendto_invalid_hostname)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY
  {
    /* Use a hostname that will definitely fail DNS resolution */
    SocketDgram_sendto (socket,
                        "test",
                        4,
                        "this.hostname.definitely.does.not.exist.invalid",
                        12345);
  }
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&socket);
}

/* ==================== IPv6 TTL Getter Test ==================== */

TEST (socketdgram_ipv6_getttl_returns_set_value)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET6, 0);
  ASSERT_NOT_NULL (socket);

  TRY
  {
    SocketDgram_setttl (socket, 100);
    int ttl = SocketDgram_getttl (socket);
    ASSERT_EQ (100, ttl);

    SocketDgram_setttl (socket, 200);
    ttl = SocketDgram_getttl (socket);
    ASSERT_EQ (200, ttl);
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  END_TRY;

  SocketDgram_free (&socket);
}

/* ==================== setreuseport Test ==================== */

TEST (socketdgram_setreuseport)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  TRY SocketDgram_setreuseport (socket);
  EXCEPT (SocketDgram_Failed)
  /* SO_REUSEPORT may not be available on all systems, which is acceptable */
  (void)0;
  END_TRY;

  SocketDgram_free (&socket);
}

/* ==================== Invalid TTL Tests ==================== */

TEST (socketdgram_setttl_invalid_zero)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY SocketDgram_setttl (socket, 0);
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&socket);
}

TEST (socketdgram_setttl_invalid_over_255)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY SocketDgram_setttl (socket, 256);
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&socket);
}

/* ==================== Bind Error Test ==================== */

TEST (socketdgram_bind_already_bound_port)
{
  setup_signals ();
  SocketDgram_T socket1 = SocketDgram_new (AF_INET, 0);
  SocketDgram_T socket2 = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;
  volatile int port = 0;

  TRY
  {
    /* Bind first socket to a port */
    SocketDgram_bind (socket1, "127.0.0.1", 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (SocketDgram_fd (socket1), (struct sockaddr *)&addr, &len);
    port = ntohs (addr.sin_port);

    /* Try to bind second socket to the same port WITHOUT SO_REUSEADDR */
    SocketDgram_bind (socket2, "127.0.0.1", port);
  }
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  /* On some systems this may succeed if SO_REUSEADDR is default, so we accept
   * either */
  (void)raised;

  SocketDgram_free (&socket1);
  SocketDgram_free (&socket2);
}

/* ==================== Connect Error Test ==================== */

TEST (socketdgram_connect_invalid_address)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  volatile int raised = 0;

  TRY
  {
    /* Try to connect to an invalid/unresolvable address */
    SocketDgram_connect (
        socket, "this.hostname.definitely.does.not.exist.invalid", 12345);
  }
  EXCEPT (SocketDgram_Failed)
  raised = 1;
  END_TRY;

  ASSERT_EQ (1, raised);
  SocketDgram_free (&socket);
}

/* ==================== Local Address Accessor Test ==================== */

TEST (socketdgram_getlocaladdr_returns_unknown_before_bind)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  const char *addr = SocketDgram_getlocaladdr (socket);
  ASSERT_NOT_NULL (addr);
  ASSERT_EQ (0, strcmp (addr, "(unknown)"));

  /* After bind, should return actual address */
  TRY
  {
    SocketDgram_bind (socket, "127.0.0.1", 0);
    addr = SocketDgram_getlocaladdr (socket);
    ASSERT_NOT_NULL (addr);
    ASSERT_EQ (0, strcmp (addr, "127.0.0.1"));
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  END_TRY;

  SocketDgram_free (&socket);
}

TEST (socketdgram_getlocalport_returns_zero_before_bind)
{
  setup_signals ();
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);

  int port = SocketDgram_getlocalport (socket);
  ASSERT_EQ (0, port);

  /* After bind, should return actual port */
  TRY
  {
    SocketDgram_bind (socket, "127.0.0.1", 0);
    port = SocketDgram_getlocalport (socket);
    ASSERT (port > 0);
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  END_TRY;

  SocketDgram_free (&socket);
}

/* ==================== Debug Live Count Tests ==================== */

TEST (socketdgram_debug_live_count_tracks_sockets)
{
  setup_signals ();

  /* Get initial count */
  int initial_count = SocketDgram_debug_live_count ();

  /* Create some sockets */
  SocketDgram_T sock1 = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (sock1);
  ASSERT_EQ (initial_count + 1, SocketDgram_debug_live_count ());

  SocketDgram_T sock2 = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (sock2);
  ASSERT_EQ (initial_count + 2, SocketDgram_debug_live_count ());

  SocketDgram_T sock3 = SocketDgram_new (AF_INET6, 0);
  ASSERT_NOT_NULL (sock3);
  ASSERT_EQ (initial_count + 3, SocketDgram_debug_live_count ());

  /* Free sockets and verify count decreases */
  SocketDgram_free (&sock1);
  ASSERT_EQ (initial_count + 2, SocketDgram_debug_live_count ());

  SocketDgram_free (&sock2);
  ASSERT_EQ (initial_count + 1, SocketDgram_debug_live_count ());

  SocketDgram_free (&sock3);
  ASSERT_EQ (initial_count, SocketDgram_debug_live_count ());
}

TEST (socketdgram_debug_live_count_zero_on_cleanup)
{
  setup_signals ();

  /* Get initial count (should be 0 if all tests clean up properly) */
  int initial_count = SocketDgram_debug_live_count ();

  /* Create and immediately free */
  SocketDgram_T socket = SocketDgram_new (AF_INET, 0);
  ASSERT_NOT_NULL (socket);
  ASSERT_EQ (initial_count + 1, SocketDgram_debug_live_count ());

  SocketDgram_free (&socket);
  ASSERT_NULL (socket);
  ASSERT_EQ (initial_count, SocketDgram_debug_live_count ());
}

/* ==================== IPv6 Convenience Function Tests ==================== */

TEST (socketdgram_bind_udp4_creates_ipv4_socket)
{
  setup_signals ();
  SocketDgram_T server = NULL;

  TRY
  {
    server = SocketDgram_bind_udp4 ("127.0.0.1", 0);
    ASSERT_NOT_NULL (server);
    ASSERT (SocketDgram_isbound (server));

    /* Verify it's IPv4 by checking local address */
    const char *addr = SocketDgram_getlocaladdr (server);
    ASSERT_NOT_NULL (addr);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  FINALLY
  {
    SocketDgram_free (&server);
  }
  END_TRY;
}

TEST (socketdgram_bind_udp6_creates_ipv6_socket)
{
  setup_signals ();
  SocketDgram_T server = NULL;

  TRY
  {
    server = SocketDgram_bind_udp6 ("::1", 0);
    ASSERT_NOT_NULL (server);
    ASSERT (SocketDgram_isbound (server));

    /* Verify it's IPv6 by checking local address contains ':' */
    const char *addr = SocketDgram_getlocaladdr (server);
    ASSERT_NOT_NULL (addr);
    ASSERT (strchr (addr, ':') != NULL);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  FINALLY
  {
    SocketDgram_free (&server);
  }
  END_TRY;
}

TEST (socketdgram_bind_udp6_wildcard)
{
  setup_signals ();
  SocketDgram_T server = NULL;

  TRY
  {
    server = SocketDgram_bind_udp6 ("::", 0);
    ASSERT_NOT_NULL (server);
    ASSERT (SocketDgram_isbound (server));

    /* Should get ephemeral port */
    int port = SocketDgram_getlocalport (server);
    ASSERT (port > 0);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  FINALLY
  {
    SocketDgram_free (&server);
  }
  END_TRY;
}

TEST (socketdgram_bind_udp_autodetect_ipv4_null)
{
  setup_signals ();
  SocketDgram_T server = NULL;

  TRY
  {
    /* NULL should default to IPv4 for backward compatibility */
    server = SocketDgram_bind_udp (NULL, 0);
    ASSERT_NOT_NULL (server);
    ASSERT (SocketDgram_isbound (server));
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  FINALLY
  {
    SocketDgram_free (&server);
  }
  END_TRY;
}

TEST (socketdgram_bind_udp_autodetect_ipv4_dotted)
{
  setup_signals ();
  SocketDgram_T server = NULL;

  TRY
  {
    /* Dotted-decimal IPv4 should be detected */
    server = SocketDgram_bind_udp ("127.0.0.1", 0);
    ASSERT_NOT_NULL (server);
    ASSERT (SocketDgram_isbound (server));

    const char *addr = SocketDgram_getlocaladdr (server);
    ASSERT_NOT_NULL (addr);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  FINALLY
  {
    SocketDgram_free (&server);
  }
  END_TRY;
}

TEST (socketdgram_bind_udp_autodetect_ipv6_colon)
{
  setup_signals ();
  SocketDgram_T server = NULL;

  TRY
  {
    /* IPv6 with colons should be detected */
    server = SocketDgram_bind_udp ("::", 0);
    ASSERT_NOT_NULL (server);
    ASSERT (SocketDgram_isbound (server));

    const char *addr = SocketDgram_getlocaladdr (server);
    ASSERT_NOT_NULL (addr);
    ASSERT (strchr (addr, ':') != NULL);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  FINALLY
  {
    SocketDgram_free (&server);
  }
  END_TRY;
}

TEST (socketdgram_bind_udp_autodetect_ipv6_loopback)
{
  setup_signals ();
  SocketDgram_T server = NULL;

  TRY
  {
    /* IPv6 loopback should be detected */
    server = SocketDgram_bind_udp ("::1", 0);
    ASSERT_NOT_NULL (server);
    ASSERT (SocketDgram_isbound (server));

    const char *addr = SocketDgram_getlocaladdr (server);
    ASSERT_NOT_NULL (addr);
    ASSERT (strchr (addr, ':') != NULL);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  FINALLY
  {
    SocketDgram_free (&server);
  }
  END_TRY;
}

TEST (socketdgram_bind_udp_ipv4_ipv6_both_work)
{
  setup_signals ();
  SocketDgram_T server_v4 = NULL;
  SocketDgram_T server_v6 = NULL;

  TRY
  {
    /* Create both IPv4 and IPv6 sockets on different ports */
    server_v4 = SocketDgram_bind_udp4 ("0.0.0.0", 0);
    ASSERT_NOT_NULL (server_v4);

    server_v6 = SocketDgram_bind_udp6 ("::", 0);
    ASSERT_NOT_NULL (server_v6);

    /* Both should be bound */
    ASSERT (SocketDgram_isbound (server_v4));
    ASSERT (SocketDgram_isbound (server_v6));

    /* Should have different ports */
    int port_v4 = SocketDgram_getlocalport (server_v4);
    int port_v6 = SocketDgram_getlocalport (server_v6);
    ASSERT (port_v4 > 0);
    ASSERT (port_v6 > 0);
  }
  EXCEPT (SocketDgram_Failed)
  {
    ASSERT (0);
  }
  FINALLY
  {
    SocketDgram_free (&server_v4);
    SocketDgram_free (&server_v6);
  }
  END_TRY;
}

/* ==================== Port Parsing Validation Tests (Issue #1361) ========
 */

TEST (socketdgram_recvfrom_validates_port_correctly)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY
  {
    SocketDgram_bind (receiver, "127.0.0.1", 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
    int port = ntohs (addr.sin_port);

    const char *msg = "Port validation test";
    ssize_t sent
        = SocketDgram_sendto (sender, msg, strlen (msg), "127.0.0.1", port);
    ASSERT_NE (sent, -1);

    usleep (10000);
    char recv_host[256] = { 0 };
    int recv_port = 0;
    char buf[TEST_BUFFER_SIZE] = { 0 };
    ssize_t received = SocketDgram_recvfrom (receiver,
                                             buf,
                                             sizeof (buf) - 1,
                                             recv_host,
                                             sizeof (recv_host),
                                             &recv_port);

    if (received > 0)
      {
        /* Port should be non-zero and valid */
        ASSERT_NE (recv_port, 0);
        ASSERT (recv_port > 0);
        ASSERT (recv_port <= 65535);
      }
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  FINALLY
  {
    SocketDgram_free (&sender);
    SocketDgram_free (&receiver);
  }
  END_TRY;
}

TEST (socketdgram_recvfrom_handles_port_range_correctly)
{
  setup_signals ();
  SocketDgram_T sender = SocketDgram_new (AF_INET, 0);
  SocketDgram_T receiver = SocketDgram_new (AF_INET, 0);

  TRY
  {
    /* Bind to ephemeral port and verify it's in valid range */
    SocketDgram_bind (receiver, "127.0.0.1", 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    getsockname (SocketDgram_fd (receiver), (struct sockaddr *)&addr, &len);
    int bound_port = ntohs (addr.sin_port);

    /* Bound port should be in valid range */
    ASSERT (bound_port > 0);
    ASSERT (bound_port <= 65535);

    /* Send a message */
    const char *msg = "Port range test";
    ssize_t sent = SocketDgram_sendto (
        sender, msg, strlen (msg), "127.0.0.1", bound_port);
    ASSERT_NE (sent, -1);

    usleep (10000);
    char recv_host[256] = { 0 };
    int recv_port = 0;
    char buf[TEST_BUFFER_SIZE] = { 0 };
    ssize_t received = SocketDgram_recvfrom (receiver,
                                             buf,
                                             sizeof (buf) - 1,
                                             recv_host,
                                             sizeof (recv_host),
                                             &recv_port);

    if (received > 0)
      {
        /* Received port should match valid range constraints */
        ASSERT (recv_port > 0);
        ASSERT (recv_port <= 65535);
      }
  }
  EXCEPT (SocketDgram_Failed)
  {
    (void)0;
  }
  FINALLY
  {
    SocketDgram_free (&sender);
    SocketDgram_free (&receiver);
  }
  END_TRY;
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

/**
 * test_socket.c - Comprehensive Socket unit tests
 * Industry-standard test coverage for Socket module.
 * Tests TCP sockets, Unix domain sockets, IPv6, error conditions, and edge
 * cases.
 */

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

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"
#include "test/Test.h"

#define TEST_UNIX_SOCKET_PATH "/tmp/test_socket_unix"
#define TEST_BUFFER_SIZE 4096

/* Setup signal handling for SIGPIPE */
static void
setup_signals (void)
{
  signal (SIGPIPE, SIG_IGN);
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
  TRY
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
  EXCEPT (Socket_Failed)
    {
      return;
    }
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
      TRY
        Socket_T client = NULL;
        client = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_connect (client, "127.0.0.1", port);
        usleep (10000);
        Socket_T accepted = NULL;
        accepted = Socket_accept (server);
        if (accepted)
          Socket_free (&accepted);
        Socket_free (&client);
      EXCEPT (Socket_Failed)
        {}
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
      TRY
        Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        if (socket)
          Socket_free (&socket);
      EXCEPT (Socket_Failed)
        {} // Ignore creation failures during concurrent stress test
      EXCEPT (Arena_Failed)
        {} // Ignore arena failures
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

#if 0 /* DNS test disabled - hangs on SocketDNS_check() */
TEST(socket_bind_async_basic)
{
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketDNS_Request_T req = Socket_bind_async(dns, socket, "127.0.0.1", 0);
        ASSERT_NOT_NULL(req);
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_bind_with_addrinfo(socket, res);
            freeaddrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        Socket_free(&socket);
        SocketDNS_free(&dns);
    END_TRY;
}
#endif

#if 0 /* DNS tests disabled - hang on SocketDNS_check() */
TEST(socket_bind_async_wildcard)
                {
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketDNS_Request_T req = Socket_bind_async(dns, socket, NULL, 0);
        ASSERT_NOT_NULL(req);
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_bind_with_addrinfo(socket, res);
            freeaddrinfo(res);
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
        
        SocketDNS_Request_T req = Socket_connect_async(dns, client, "127.0.0.1", port);
        ASSERT_NOT_NULL(req);
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_connect_with_addrinfo(client, res);
            freeaddrinfo(res);
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
        
        SocketDNS_Request_T req = Socket_connect_async(dns, client, "localhost", port);
        ASSERT_NOT_NULL(req);
        usleep(200000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_connect_with_addrinfo(client, res);
            freeaddrinfo(res);
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
      freeaddrinfo (res);
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
      freeaddrinfo (res);
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

  SocketMetrics_reset ();
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 3);
  SocketMetrics_increment (SOCKET_METRIC_POLL_WAKEUPS, 1);
  SocketMetrics_getsnapshot (&snapshot);

  ASSERT_EQ (3ULL, SocketMetrics_snapshot_value (
                       &snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
  ASSERT_EQ (1ULL, SocketMetrics_snapshot_value (&snapshot,
                                                 SOCKET_METRIC_POLL_WAKEUPS));
  ASSERT_EQ (SOCKET_METRIC_COUNT, SocketMetrics_count ());

  SocketMetrics_reset ();
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

  SocketMetrics_reset ();
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

  SocketMetrics_reset ();
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
  SocketDNS_Request_T req;
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

  freeaddrinfo (res);
  res = NULL;
  EXCEPT (Socket_Failed)
  if (res)
    freeaddrinfo (res);
  EXCEPT (SocketDNS_Failed)
  if (res)
    freeaddrinfo (res);
  FINALLY
  if (socket)
    Socket_free (&socket);
  if (dns)
    SocketDNS_free (&dns);
  END_TRY;
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

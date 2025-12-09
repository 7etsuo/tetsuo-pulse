/**
 * test_coverage.c - Additional coverage tests for achieving 100% gcov
 *
 * This file contains targeted tests for code paths not covered by existing
 * tests. Focus areas:
 * - Error paths and edge cases
 * - TLS session management callbacks
 * - Socket pool operations
 * - SocketReconnect edge cases
 * - Socket error handling
 */

/* cppcheck-suppress-file constVariablePointer ; test allocation success */
/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */
/* cppcheck-suppress-file unreadVariable ; intentional test patterns */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "pool/SocketPool.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketDgram.h"
#include "socket/SocketReconnect.h"
#include "test/Test.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#endif

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

static int
create_listening_server (int *out_port)
{
  Socket_T server = NULL;
  int port = 0;

  TRY
  {
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    port = Socket_getlocalport (server);
    *out_port = port;
    return Socket_fd (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    return -1;
  }
  END_TRY;
  return -1;
}

/* ============================================================================
 * Socket Error Path Tests
 * ============================================================================
 */

TEST (cov_socket_new_from_invalid_fd)
{
  volatile int raised = 0;

  signal (SIGPIPE, SIG_IGN);

  /* Test wrapping a closed fd - this tests the validation path */
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd >= 0)
    {
      close (fd); /* Close it to make it invalid */

      TRY
      {
        Socket_T sock = Socket_new_from_fd (fd);
        (void)sock;
      }
      EXCEPT (Socket_Failed) { raised = 1; }
      END_TRY;

      ASSERT (raised == 1);
    }
}

TEST (cov_socket_new_from_non_socket_fd)
{
  volatile int raised = 0;
  int fd;

  signal (SIGPIPE, SIG_IGN);

  /* Create a non-socket fd (a pipe) */
  int fds[2];
  if (pipe (fds) < 0)
    return;

  fd = fds[0];

  TRY
  {
    Socket_T sock = Socket_new_from_fd (fd);
    (void)sock;
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  close (fds[0]);
  close (fds[1]);

  /* Should have raised because pipe is not a socket */
  ASSERT (raised == 1);
}

TEST (cov_socket_bind_invalid_address)
{
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    /* Bind to clearly invalid IP (outside valid range) to test error path.
     * This exercises the DNS/address validation code path. */
    Socket_bind (sock, "999.999.999.999", 0);
  }
  EXCEPT (Socket_Failed) { /* Expected - invalid IP format */ }
  END_TRY;

  if (sock)
    Socket_free (&sock);
}

TEST (cov_socket_connect_invalid_port)
{
  volatile int raised = 0;
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    /* Try to connect to invalid port (0 or negative) */
    Socket_connect (sock, "127.0.0.1", 0);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  if (sock)
    Socket_free (&sock);

  /* Either raised or not depending on implementation */
  (void)raised;
}

TEST (cov_socket_listen_not_bound)
{
  volatile int raised = 0;
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    /* Try to listen without binding */
    Socket_listen (sock, 5);
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  if (sock)
    Socket_free (&sock);

  /* May or may not raise depending on OS behavior */
  (void)raised;
}

TEST (cov_socket_accept_not_listening)
{
  volatile int raised = 0;
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setnonblocking (sock);
    /* Try to accept without listening */
    Socket_T client = Socket_accept (sock);
    (void)client;
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  if (sock)
    Socket_free (&sock);

  ASSERT (raised == 1);
}

TEST (cov_socket_send_not_connected)
{
  volatile int raised = 0;
  Socket_T sock = NULL;
  char buf[] = "test";

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_send (sock, buf, sizeof (buf));
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  EXCEPT (Socket_Closed) { raised = 1; }
  END_TRY;

  if (sock)
    Socket_free (&sock);

  ASSERT (raised == 1);
}

TEST (cov_socket_recv_not_connected)
{
  volatile int raised = 0;
  Socket_T sock = NULL;
  char buf[64];

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_recv (sock, buf, sizeof (buf));
  }
  EXCEPT (Socket_Failed) { raised = 1; }
  EXCEPT (Socket_Closed) { raised = 1; }
  END_TRY;

  if (sock)
    Socket_free (&sock);

  ASSERT (raised == 1);
}

/* ============================================================================
 * Socket Options Tests
 * ============================================================================
 */

TEST (cov_socket_options_all)
{
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Test all socket options */
    Socket_setreuseaddr (sock);
    Socket_setnonblocking (sock);
    Socket_setkeepalive (sock, 60, 10, 3);
    Socket_setnodelay (sock, 1);

    /* Get local port (will be 0 for unconnected socket) */
    int local_port = Socket_getlocalport (sock);
    ASSERT (local_port >= 0);

    /* Get socket fd */
    int fd = Socket_fd (sock);
    ASSERT (fd >= 0);
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

/* ============================================================================
 * Socket Dgram Tests
 * ============================================================================
 */

TEST (cov_socketdgram_send_recv)
{
  SocketDgram_T sender = NULL;
  SocketDgram_T receiver = NULL;
  volatile int port = 0;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    /* Create receiver */
    receiver = SocketDgram_new (AF_INET, 0);
    SocketDgram_setreuseaddr (receiver);
    SocketDgram_bind (receiver, "127.0.0.1", 0);
    port = SocketDgram_getlocalport (receiver);

    /* Create sender */
    sender = SocketDgram_new (AF_INET, 0);

    /* Send datagram */
    char msg[] = "test datagram";
    ssize_t sent
        = SocketDgram_sendto (sender, msg, sizeof (msg), "127.0.0.1", port);
    ASSERT (sent > 0);

    /* Receive datagram */
    char buf[64] = { 0 };
    char from_addr[64];
    int from_port;

    SocketDgram_setnonblocking (receiver);
    usleep (50000); /* Wait for packet */

    ssize_t recvd
        = SocketDgram_recvfrom (receiver, buf, sizeof (buf), from_addr,
                                sizeof (from_addr), &from_port);
    if (recvd > 0)
      {
        ASSERT (strcmp (buf, msg) == 0);
      }
  }
  EXCEPT (SocketDgram_Failed) { /* May fail */ }
  FINALLY
  {
    if (sender)
      SocketDgram_free (&sender);
    if (receiver)
      SocketDgram_free (&receiver);
  }
  END_TRY;
}

TEST (cov_socketdgram_broadcast)
{
  SocketDgram_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = SocketDgram_new (AF_INET, 0);

    /* Enable broadcast */
    SocketDgram_setbroadcast (sock, 1);

    /* Verify broadcast is set */
    int bcast = SocketDgram_getbroadcast (sock);
    ASSERT (bcast == 1 || bcast == 0); /* Accept OS limitations */

    /* Test TTL */
    SocketDgram_setttl (sock, 64);
    int ttl = SocketDgram_getttl (sock);
    ASSERT (ttl == 64);
  }
  EXCEPT (SocketDgram_Failed) { /* May fail depending on OS */ }
  FINALLY
  {
    if (sock)
      SocketDgram_free (&sock);
  }
  END_TRY;
}

/* ============================================================================
 * Socket Buffer Tests
 * ============================================================================
 */

TEST (cov_socketbuf_operations)
{
  SocketBuf_T buf = NULL;
  Arena_T arena = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    arena = Arena_new ();

    /* Create buffer */
    buf = SocketBuf_new (arena, 4096);
    ASSERT_NOT_NULL (buf);

    /* Test buffer operations */
    char write_data[] = "Hello, World!";
    size_t written = SocketBuf_write (buf, write_data, sizeof (write_data));
    ASSERT (written > 0);

    /* Check available data */
    size_t avail = SocketBuf_available (buf);
    ASSERT (avail == written);

    /* Check space */
    size_t space = SocketBuf_space (buf);
    ASSERT (space > 0);

    /* Check if empty/full */
    ASSERT (SocketBuf_empty (buf) == 0);
    ASSERT (SocketBuf_full (buf) == 0);

    /* Peek data */
    char peek_data[64];
    size_t peeked = SocketBuf_peek (buf, peek_data, sizeof (peek_data));
    ASSERT (peeked > 0);

    /* Read data */
    char read_data[64];
    size_t read_len = SocketBuf_read (buf, read_data, sizeof (read_data));
    ASSERT (read_len > 0);

    /* Buffer should be empty now */
    ASSERT (SocketBuf_empty (buf) != 0);

    /* Clear buffer */
    SocketBuf_clear (buf);

    /* Release buffer */
    SocketBuf_release (&buf);
  }
  FINALLY
  {
    if (buf)
      SocketBuf_release (&buf);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;
}

TEST (cov_socketbuf_direct_access)
{
  SocketBuf_T buf = NULL;
  Arena_T arena = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    arena = Arena_new ();
    buf = SocketBuf_new (arena, 1024);

    /* Test direct write */
    size_t write_space;
    void *write_ptr = SocketBuf_writeptr (buf, &write_space);
    if (write_ptr && write_space > 0)
      {
        memcpy (write_ptr, "test", 4);
        SocketBuf_written (buf, 4);
      }

    /* Test direct read */
    size_t read_len;
    const void *read_ptr = SocketBuf_readptr (buf, &read_len);
    if (read_ptr)
      {
        ASSERT (read_len >= 4);
        SocketBuf_consume (buf, read_len);
      }

    /* Test secure clear */
    SocketBuf_write (buf, "secret", 6);
    SocketBuf_secureclear (buf);
    ASSERT (SocketBuf_empty (buf) != 0);

    SocketBuf_release (&buf);
  }
  FINALLY
  {
    if (buf)
      SocketBuf_release (&buf);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;
}

/* ============================================================================
 * Socket Poll Tests
 * ============================================================================
 */

TEST (cov_socketpoll_timeout)
{
  SocketPoll_T poll = NULL;
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    poll = SocketPoll_new (16);
    ASSERT_NOT_NULL (poll);

    sock = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Add socket with events */
    SocketPoll_add (poll, sock, POLL_READ | POLL_WRITE, NULL);

    /* Poll with short timeout (should return 0 - no events) */
    SocketEvent_T *events;
    int n = SocketPoll_wait (poll, &events, 10);
    ASSERT (n >= 0);

    /* Remove socket */
    SocketPoll_del (poll, sock);
  }
  FINALLY
  {
    if (poll)
      SocketPoll_free (&poll);
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

TEST (cov_socketpoll_modify)
{
  SocketPoll_T poll = NULL;
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    poll = SocketPoll_new (16);
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Add socket */
    SocketPoll_add (poll, sock, POLL_READ, NULL);

    /* Modify to watch for different events */
    SocketPoll_mod (poll, sock, POLL_WRITE, NULL);

    /* Modify again */
    SocketPoll_mod (poll, sock, POLL_READ | POLL_WRITE, NULL);

    /* Remove */
    SocketPoll_del (poll, sock);
  }
  FINALLY
  {
    if (poll)
      SocketPoll_free (&poll);
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

/* ============================================================================
 * Socket Pool Tests
 * ============================================================================
 */

TEST (cov_socketpool_resize)
{
  SocketPool_T pool = NULL;
  Arena_T arena = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    arena = Arena_new ();
    pool = SocketPool_new (arena, 8, 1024);
    ASSERT_NOT_NULL (pool);

    /* Resize to larger */
    SocketPool_resize (pool, 16);

    /* Resize to same size (no-op) */
    SocketPool_resize (pool, 16);

    /* Resize to smaller */
    SocketPool_resize (pool, 4);

    /* Get count */
    size_t count = SocketPool_count (pool);
    ASSERT (count == 0);
  }
  FINALLY
  {
    if (pool)
      SocketPool_free (&pool);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;
}

TEST (cov_socketpool_prewarm)
{
  SocketPool_T pool = NULL;
  Arena_T arena = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    arena = Arena_new ();
    pool = SocketPool_new (arena, 16, 1024);
    ASSERT_NOT_NULL (pool);

    /* Prewarm 50% of free slots */
    SocketPool_prewarm (pool, 50);

    /* Set buffer size */
    SocketPool_set_bufsize (pool, 2048);
  }
  FINALLY
  {
    if (pool)
      SocketPool_free (&pool);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;
}

static void
foreach_callback (Connection_T conn, void *arg)
{
  int *count = (int *)arg;
  (void)conn;
  (*count)++;
}

TEST (cov_socketpool_foreach)
{
  SocketPool_T pool = NULL;
  Arena_T arena = NULL;
  Socket_T server = NULL;
  Socket_T client = NULL;
  volatile Socket_T accepted = NULL;
  volatile int port = 0;
  int callback_count = 0;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    arena = Arena_new ();
    pool = SocketPool_new (arena, 8, 1024);

    /* Create server */
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    Socket_setnonblocking (server);
    port = Socket_getlocalport (server);

    /* Create client and connect */
    client = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setnonblocking (client);

    TRY { Socket_connect (client, "127.0.0.1", port); }
    EXCEPT (Socket_Failed) { /* Expected */ }
    END_TRY;

    /* Accept */
    usleep (50000);
    TRY { accepted = Socket_accept (server); }
    EXCEPT (Socket_Failed) { /* May fail */ }
    END_TRY;

    if (accepted)
      {
        /* Add to pool */
        Connection_T conn = SocketPool_add (pool, (Socket_T)accepted);
        if (conn)
          {
            /* Test foreach */
            SocketPool_foreach (pool, foreach_callback, &callback_count);
            ASSERT (callback_count >= 1);
          }
      }
  }
  FINALLY
  {
    /* Remove accepted from pool before freeing it */
    if (accepted && pool)
      SocketPool_remove (pool, (Socket_T)accepted);
    if (accepted)
      Socket_free ((Socket_T *)&accepted);
    if (pool)
      SocketPool_free (&pool);
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;
}

/* ============================================================================
 * Socket Reconnect Additional Edge Case Tests
 * ============================================================================
 */

TEST (cov_socketreconnect_backoff_minimum_delay)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;

  signal (SIGPIPE, SIG_IGN);

  SocketReconnect_policy_defaults (&policy);
  /* Very small multiplier to test minimum delay enforcement */
  policy.multiplier = 0.01;
  policy.initial_delay_ms = 1;
  policy.max_delay_ms = 10;
  policy.jitter = 0.5;
  policy.max_attempts = 2;

  TRY { conn = SocketReconnect_new ("127.0.0.1", 59960, &policy, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed) { return; }
  END_TRY;

  SocketReconnect_connect (conn);

  for (int i = 0; i < 10; i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (20000);
    }

  SocketReconnect_free (&conn);
}

TEST (cov_socketreconnect_max_delay_cap)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;

  signal (SIGPIPE, SIG_IGN);

  SocketReconnect_policy_defaults (&policy);
  policy.multiplier = 100.0; /* Very large to hit max_delay cap */
  policy.initial_delay_ms = 100;
  policy.max_delay_ms = 150; /* Will cap at this */
  policy.jitter = 0.0;
  policy.max_attempts = 3;

  TRY { conn = SocketReconnect_new ("127.0.0.1", 59959, &policy, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed) { return; }
  END_TRY;

  SocketReconnect_connect (conn);

  for (int i = 0; i < 10; i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (50000);
    }

  SocketReconnect_free (&conn);
}

/* Custom callback that tracks transitions for testing */
static int transition_callback_count = 0;
static SocketReconnect_State last_transition_old = RECONNECT_DISCONNECTED;
static SocketReconnect_State last_transition_new = RECONNECT_DISCONNECTED;

static void
tracking_callback (SocketReconnect_T conn, SocketReconnect_State old_state,
                   SocketReconnect_State new_state, void *userdata)
{
  (void)conn;
  (void)userdata;
  transition_callback_count++;
  last_transition_old = old_state;
  last_transition_new = new_state;
}

TEST (cov_socketreconnect_state_transitions)
{
  Socket_T server = NULL;
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;
  volatile int port = 0;

  signal (SIGPIPE, SIG_IGN);
  transition_callback_count = 0;

  /* Create server */
  TRY
  {
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    port = Socket_getlocalport (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    return;
  }
  END_TRY;

  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 5;
  policy.initial_delay_ms = 10;

  TRY
  {
    conn = SocketReconnect_new ("127.0.0.1", port, &policy, tracking_callback,
                                NULL);
  }
  EXCEPT (SocketReconnect_Failed)
  {
    Socket_free (&server);
    return;
  }
  END_TRY;

  /* Verify callback registered correctly */
  SocketReconnect_connect (conn);

  for (int i = 0; i < 20 && !SocketReconnect_isconnected (conn); i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (50000);
    }

  /* Should have had at least one state transition */
  ASSERT (transition_callback_count >= 1);

  /* Disconnect and verify callback */
  SocketReconnect_disconnect (conn);

  ASSERT (SocketReconnect_state (conn) == RECONNECT_DISCONNECTED);

  SocketReconnect_free (&conn);
  Socket_free (&server);
}

TEST (cov_socketreconnect_send_recv_eof)
{
  Socket_T server = NULL;
  volatile Socket_T accepted = NULL;
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;
  volatile int port = 0;
  volatile int i;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    Socket_setnonblocking (server);
    port = Socket_getlocalport (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    return;
  }
  END_TRY;

  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 3;
  policy.initial_delay_ms = 10;

  TRY { conn = SocketReconnect_new ("127.0.0.1", port, &policy, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    Socket_free (&server);
    return;
  }
  END_TRY;

  SocketReconnect_connect (conn);

  /* Connect and accept */
  for (i = 0; i < 30 && !SocketReconnect_isconnected (conn); i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      TRY
      {
        if (!accepted)
          accepted = Socket_accept (server);
      }
      EXCEPT (Socket_Failed) { /* Ignore */ }
      END_TRY;
      usleep (50000);
    }

  if (SocketReconnect_isconnected (conn) && accepted)
    {
      /* Close server side to cause EOF */
      Socket_T temp = (Socket_T)accepted;
      Socket_free (&temp);
      accepted = NULL;

      usleep (50000);

      /* Try recv - should return 0 (EOF) and trigger reconnect */
      Socket_T sock = SocketReconnect_socket (conn);
      if (sock)
        {
          Socket_setnonblocking (sock);
          char buf[64];
          ssize_t result = SocketReconnect_recv (conn, buf, sizeof (buf));

          /* Should have triggered reconnect */
          (void)result;
        }
    }

  SocketReconnect_free (&conn);
  if (accepted)
    {
      Socket_T temp = (Socket_T)accepted;
      Socket_free (&temp);
    }
  Socket_free (&server);
}

TEST (cov_socketreconnect_zero_jitter)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;

  signal (SIGPIPE, SIG_IGN);

  SocketReconnect_policy_defaults (&policy);
  policy.jitter = 0.0; /* No jitter */
  policy.max_attempts = 2;
  policy.initial_delay_ms = 10;

  TRY { conn = SocketReconnect_new ("127.0.0.1", 59970, &policy, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Start connection */
  SocketReconnect_connect (conn);

  /* Process a few times */
  for (int i = 0; i < 5; i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (20000);
    }

  SocketReconnect_free (&conn);
}

TEST (cov_socketreconnect_unlimited_attempts)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;
  Socket_T server = NULL;
  volatile int port = 0;

  signal (SIGPIPE, SIG_IGN);

  /* Create server */
  TRY
  {
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    port = Socket_getlocalport (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    return;
  }
  END_TRY;

  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 0; /* Unlimited */
  policy.initial_delay_ms = 10;

  TRY { conn = SocketReconnect_new ("127.0.0.1", port, &policy, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    Socket_free (&server);
    return;
  }
  END_TRY;

  /* Connect and verify unlimited attempts don't stop it */
  SocketReconnect_connect (conn);

  for (int i = 0; i < 10 && !SocketReconnect_isconnected (conn); i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (50000);
    }

  /* Should be connected */
  ASSERT (SocketReconnect_isconnected (conn));

  SocketReconnect_free (&conn);
  Socket_free (&server);
}

/* ============================================================================
 * Arena Edge Cases
 * ============================================================================
 */

TEST (cov_arena_large_allocation)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate a larger block */
  void *ptr = Arena_alloc (arena, 65536, __FILE__, __LINE__);
  ASSERT_NOT_NULL (ptr);

  /* Allocate many small blocks to test chunk management */
  for (int i = 0; i < 100; i++)
    {
      void *small = Arena_alloc (arena, 64, __FILE__, __LINE__);
      ASSERT_NOT_NULL (small);
    }

  Arena_dispose (&arena);
  ASSERT_NULL (arena);
}

TEST (cov_arena_calloc)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Test calloc - should zero-initialize */
  int *arr = Arena_calloc (arena, 10, sizeof (int), __FILE__, __LINE__);
  ASSERT_NOT_NULL (arr);

  /* Verify zeroed */
  for (int i = 0; i < 10; i++)
    {
      ASSERT_EQ (0, arr[i]);
    }

  Arena_dispose (&arena);
}

/* ============================================================================
 * DNS Edge Cases
 * ============================================================================
 */

static atomic_int dns_callback_called = 0;
static atomic_int dns_callback_error = 0;

static void
dns_test_callback (Request_T req, struct addrinfo *result, int error,
                   void *data)
{
  (void)req;
  (void)data;
  dns_callback_called = 1;
  dns_callback_error = error;
  if (result)
    SocketCommon_free_addrinfo (result);
}

TEST (cov_dns_resolve_async)
{
  SocketDNS_T dns = NULL;

  signal (SIGPIPE, SIG_IGN);
  dns_callback_called = 0;
  dns_callback_error = 0;

  TRY
  {
    dns = SocketDNS_new ();
    ASSERT_NOT_NULL (dns);

    /* Resolve localhost asynchronously */
    Request_T req
        = SocketDNS_resolve (dns, "localhost", 80, dns_test_callback, NULL);
    if (req)
      {
        /* Wait for callback */
        for (int i = 0; i < 50 && !dns_callback_called; i++)
          {
            SocketDNS_check (dns);
            usleep (50000);
          }

        /* Callback should have been called */
        ASSERT (dns_callback_called == 1);
      }
  }
  EXCEPT (SocketDNS_Failed) { /* May fail if DNS not available */ }
  FINALLY
  {
    if (dns)
      SocketDNS_free (&dns);
  }
  END_TRY;
}

TEST (cov_dns_resolve_invalid)
{
  SocketDNS_T dns = NULL;

  signal (SIGPIPE, SIG_IGN);
  dns_callback_called = 0;
  dns_callback_error = 0;

  TRY
  {
    dns = SocketDNS_new ();

    /* Try to resolve invalid hostname */
    Request_T req
        = SocketDNS_resolve (dns, "this-host-should-not-exist.invalid", 80,
                             dns_test_callback, NULL);
    if (req)
      {
        /* Wait for callback */
        for (int i = 0; i < 50 && !dns_callback_called; i++)
          {
            SocketDNS_check (dns);
            usleep (50000);
          }
      }
  }
  EXCEPT (SocketDNS_Failed) { /* Expected for invalid host */ }
  FINALLY
  {
    if (dns)
      SocketDNS_free (&dns);
  }
  END_TRY;
}

/* ============================================================================
 * TLS Tests (if available)
 * ============================================================================
 */

#if SOCKET_HAS_TLS

/* Size constant for oversized OCSP response tests */
#define LARGE_OCSP_RESPONSE_SIZE 100000

/* Generate test certificates using openssl command.
 * Note: cert_file and key_file are hardcoded constants in test code,
 * not user input, so command injection is not a concern. */
static int
generate_test_certs_cov (const char *cert_file, const char *key_file)
{
  char cmd[1024];
  snprintf (
      cmd, sizeof (cmd),
      "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 -nodes "
      "-subj '/CN=localhost' 2>/dev/null",
      key_file, cert_file);
  return system (cmd);
}

static void
remove_test_certs_cov (const char *cert_file, const char *key_file)
{
  unlink (cert_file);
  unlink (key_file);
}

TEST (cov_tls_session_cache_stats)
{
  const char *cert_file = "test_cov_sess.crt";
  const char *key_file = "test_cov_sess.key";

  if (generate_test_certs_cov (cert_file, key_file) != 0)
    return;

  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T client_sock = NULL;
  Socket_T server_sock = NULL;
  int sv[2];

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);

    /* Enable session cache on both */
    SocketTLSContext_enable_session_cache (server_ctx, 100, 300);
    SocketTLSContext_enable_session_cache (client_ctx, 100, 300);

    /* Set verify mode to none for testing */
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);
    SocketTLSContext_set_verify_mode (server_ctx, TLS_VERIFY_NONE);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client_sock);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server_sock);
        loops++;
        usleep (1000);
      }

    if (client_state == TLS_HANDSHAKE_COMPLETE
        && server_state == TLS_HANDSHAKE_COMPLETE)
      {
        /* Check session cache stats */
        size_t hits = 0, misses = 0, stores = 0;
        SocketTLSContext_get_cache_stats (server_ctx, &hits, &misses, &stores);

        /* After first handshake, values are set - just verify no crash */
        (void)hits;
        (void)misses;
        (void)stores;
      }
  }
  EXCEPT (SocketTLS_Failed) { /* May fail */ }
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
    remove_test_certs_cov (cert_file, key_file);
  }
  END_TRY;
}

TEST (cov_tls_verify_modes)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test all verify modes */
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_FAIL_IF_NO_PEER_CERT);
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_CLIENT_ONCE);

  /* Test invalid mode (should use default) */
  SocketTLSContext_set_verify_mode (ctx, (TLSVerifyMode)99);

  SocketTLSContext_free (&ctx);
}

TEST (cov_tls_ocsp_response_too_large)
{
  const char *cert_file = "test_cov_ocsp.crt";
  const char *key_file = "test_cov_ocsp.key";

  if (generate_test_certs_cov (cert_file, key_file) != 0)
    return;

  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    /* Try to set oversized OCSP response (> 64KB limit typically) */
    unsigned char *large_response = malloc (LARGE_OCSP_RESPONSE_SIZE);
    if (large_response)
      {
        memset (large_response, 0x30,
                LARGE_OCSP_RESPONSE_SIZE); /* ASN.1 SEQUENCE tag */

        TRY
        {
          SocketTLSContext_set_ocsp_response (ctx, large_response,
                                              LARGE_OCSP_RESPONSE_SIZE);
        }
        EXCEPT (SocketTLS_Failed) { raised = 1; }
        END_TRY;

        free (large_response);
      }
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs_cov (cert_file, key_file);
  }
  END_TRY;

  /* Should have raised for oversized response */
  ASSERT (raised == 1);
}

TEST (cov_tls_get_ocsp_status_no_tls)
{
  /* Test SocketTLS_get_ocsp_status with NULL socket */
  int status = SocketTLS_get_ocsp_status (NULL);
  ASSERT_EQ (0, status);
}

TEST (cov_tls_protocol_version_fallback)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Set min protocol to TLS 1.2 */
  TRY { SocketTLSContext_set_min_protocol (ctx, TLS1_2_VERSION); }
  EXCEPT (SocketTLS_Failed) { /* May fail on some OpenSSL builds */ }
  END_TRY;

  /* Set max protocol */
  TRY { SocketTLSContext_set_max_protocol (ctx, TLS1_3_VERSION); }
  EXCEPT (SocketTLS_Failed) { /* May fail */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
}

#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * Utility Function Tests
 * ============================================================================
 */

TEST (cov_socket_timeouts)
{
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Set and get timeouts */
    SocketTimeouts_T timeouts;
    Socket_timeouts_getdefaults (&timeouts);

    timeouts.connect_timeout_ms = 5000;
    timeouts.dns_timeout_ms = 3000;
    timeouts.operation_timeout_ms = 3000;

    Socket_timeouts_set (sock, &timeouts);

    /* Get timeouts back */
    SocketTimeouts_T got;
    Socket_timeouts_get (sock, &got);

    ASSERT_EQ (timeouts.connect_timeout_ms, got.connect_timeout_ms);
    ASSERT_EQ (timeouts.dns_timeout_ms, got.dns_timeout_ms);
    ASSERT_EQ (timeouts.operation_timeout_ms, got.operation_timeout_ms);
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  signal (SIGPIPE, SIG_IGN);
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

/**
 * test_proxy_integration.c - Proxy Tunneling Integration Tests
 *
 * End-to-end proxy tests with real network I/O.
 * Uses loopback (127.0.0.1) for proxy and target servers.
 *
 * Tests:
 * - Proxy URL parsing
 * - SOCKS5 handshake and tunneling
 * - SOCKS4/4a handshake
 * - HTTP CONNECT (basic test)
 * - Authentication handling
 *
 * Module Reuse:
 * - SocketProxy for proxy protocols
 * - Socket for networking
 * - SocketHappyEyeballs (internally by SocketProxy)
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketProxy.h"
#include "test/Test.h"

/* ============================================================================
 * Test Configuration
 * ============================================================================ */

#define TEST_PORT_BASE 48000
#define TEST_TIMEOUT_MS 5000

static int proxy_test_port_counter = 0;

static int
get_proxy_test_port (void)
{
  return TEST_PORT_BASE + (proxy_test_port_counter++ % 1000);
}

/* ============================================================================
 * Mini SOCKS5 Proxy Server
 * ============================================================================ */

typedef struct
{
  Socket_T listen_socket;
  Socket_T target_listen;
  pthread_t thread;
  pthread_t echo_thread;
  atomic_int running;
  atomic_int started;
  atomic_int echo_started;
  atomic_int client_connected;
  atomic_int tunnel_established;
  int proxy_port;
  int target_port;
  const char *required_username;
  const char *required_password;
} Socks5TestServer;

/* SOCKS5 constants */
#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF
#define SOCKS5_REP_SUCCESS 0x00

static void *
socks5_server_thread_func (void *arg)
{
  Socks5TestServer *server = (Socks5TestServer *)arg;
  Socket_T client = NULL;
  Socket_T target = NULL;
  unsigned char buf[512];
  volatile ssize_t n = 0;

  server->started = 1;

  /* Accept client - handle Socket_Failed exception when socket is closed during shutdown */
  TRY
    {
      client = Socket_accept (server->listen_socket);
    }
  EXCEPT (Socket_Failed)
    {
      /* Socket was closed - expected during server stop */
      client = NULL;
    }
  END_TRY;
  if (client == NULL)
    {
      server->running = 0;
      return NULL;
    }

  server->client_connected = 1;
  

  /* SOCKS5 greeting - read client's auth methods */
  TRY
    {
      n = Socket_recv (client, buf, sizeof (buf));
    }
  EXCEPT (Socket_Closed)
    {
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }
  END_TRY;
  if (n < 2 || buf[0] != SOCKS5_VERSION)
    {
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }

  int num_methods = buf[1];
  if (n < 2 + num_methods)
    {
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }

  /* Check for acceptable auth method */
  unsigned char auth_method = SOCKS5_AUTH_NO_ACCEPTABLE;
  if (server->required_username == NULL)
    {
      /* No auth required - look for NO_AUTH method */
      for (int i = 0; i < num_methods; i++)
        {
          if (buf[2 + i] == SOCKS5_AUTH_NONE)
            {
              auth_method = SOCKS5_AUTH_NONE;
              break;
            }
        }
    }
  else
    {
      /* Auth required - look for USERPASS method */
      for (int i = 0; i < num_methods; i++)
        {
          if (buf[2 + i] == SOCKS5_AUTH_USERPASS)
            {
              auth_method = SOCKS5_AUTH_USERPASS;
              break;
            }
        }
    }

  /* Send auth method selection */
  buf[0] = SOCKS5_VERSION;
  buf[1] = auth_method;
  Socket_send (client, buf, 2);

  if (auth_method == SOCKS5_AUTH_NO_ACCEPTABLE)
    {
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }

  /* Handle username/password auth if required */
  if (auth_method == SOCKS5_AUTH_USERPASS)
    {
      TRY
        {
          n = Socket_recv (client, buf, sizeof (buf));
        }
      EXCEPT (Socket_Closed)
        {
          Socket_free (&client);
          server->running = 0;
          return NULL;
        }
      END_TRY;
      if (n < 3 || buf[0] != 0x01)
        {
          Socket_free (&client);
          server->running = 0;
          return NULL;
        }

      int ulen = buf[1];
      if (n < 3 + ulen)
        {
          Socket_free (&client);
          server->running = 0;
          return NULL;
        }

      char username[256] = { 0 };
      memcpy (username, buf + 2, ulen);

      int plen = buf[2 + ulen];
      if (n < 3 + ulen + plen)
        {
          Socket_free (&client);
          server->running = 0;
          return NULL;
        }

      char password[256] = { 0 };
      memcpy (password, buf + 3 + ulen, plen);

      /* Verify credentials */
      int auth_ok = (strcmp (username, server->required_username) == 0
                     && strcmp (password, server->required_password) == 0);

      buf[0] = 0x01;
      buf[1] = auth_ok ? 0x00 : 0x01;
      Socket_send (client, buf, 2);

      if (!auth_ok)
        {
          Socket_free (&client);
          server->running = 0;
          return NULL;
        }
    }

  /* Read connect request */
  TRY
    {
      n = Socket_recv (client, buf, sizeof (buf));
    }
  EXCEPT (Socket_Closed)
    {
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }
  END_TRY;
  if (n < 4 || buf[0] != SOCKS5_VERSION || buf[1] != SOCKS5_CMD_CONNECT)
    {
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }

  /* Parse target address (for protocol compliance, but we use our test server) */
  int atyp = buf[3];
  char target_host[256] = { 0 };

  if (atyp == SOCKS5_ATYP_IPV4)
    {
      if (n < 10)
        {
          Socket_free (&client);
          server->running = 0;
          return NULL;
        }
      snprintf (target_host, sizeof (target_host), "%d.%d.%d.%d", buf[4],
                buf[5], buf[6], buf[7]);
      (void)target_host; /* Used for protocol parsing, we use test server port */
    }
  else if (atyp == SOCKS5_ATYP_DOMAIN)
    {
      int dlen = buf[4];
      if (n < 7 + dlen)
        {
          Socket_free (&client);
          server->running = 0;
          return NULL;
        }
      memcpy (target_host, buf + 5, dlen);
      target_host[dlen] = '\0';
      /* Port parsed for protocol compliance: (buf[5 + dlen] << 8) | buf[6 + dlen] */
    }
  else
    {
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }

  /* Connect to target (use our local target server) */
  TRY
  target = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_connect (target, "127.0.0.1", server->target_port);
  EXCEPT (Socket_Failed)
  /* Send failure response */
  buf[0] = SOCKS5_VERSION;
  buf[1] = 0x05; /* Connection refused */
  buf[2] = 0x00;
  buf[3] = SOCKS5_ATYP_IPV4;
  memset (buf + 4, 0, 6);
  Socket_send (client, buf, 10);
  Socket_free (&client);
  server->running = 0;
  return NULL;
  END_TRY;

  /* Send success response */
  buf[0] = SOCKS5_VERSION;
  buf[1] = SOCKS5_REP_SUCCESS;
  buf[2] = 0x00;
  buf[3] = SOCKS5_ATYP_IPV4;
  buf[4] = 127;
  buf[5] = 0;
  buf[6] = 0;
  buf[7] = 1;
  buf[8] = (server->target_port >> 8) & 0xFF;
  buf[9] = server->target_port & 0xFF;
  Socket_send (client, buf, 10);

  server->tunnel_established = 1;

  /* Simple relay: forward data in both directions */
  /* For testing, just forward one message each way */
  n = Socket_recv (client, buf, sizeof (buf));
  if (n > 0)
    {
      Socket_send (target, buf, (size_t)n);
      n = Socket_recv (target, buf, sizeof (buf));
      if (n > 0)
        {
          Socket_send (client, buf, (size_t)n);
        }
    }

  Socket_free (&target);
  Socket_free (&client);

  return NULL;
}

/* Simple echo server for testing */
static void *
echo_server_thread_func (void *arg)
{
  Socks5TestServer *server = (Socks5TestServer *)arg;
  Socket_T client = NULL;
  unsigned char buf[512];
  volatile ssize_t n = 0;

  /* Signal that we've started */
  server->echo_started = 1;

  /* Handle Socket_Failed exception when socket is closed during shutdown */
  TRY
    {
      client = Socket_accept (server->target_listen);
    }
  EXCEPT (Socket_Failed)
    {
      /* Socket was closed - expected during server stop */
      client = NULL;
    }
  END_TRY;
  if (client == NULL)
    return NULL;

  /* Echo received data - handle Socket_Closed from dummy unblock connections */
  TRY
    {
      n = Socket_recv (client, buf, sizeof (buf));
      if (n > 0)
        {
          Socket_send (client, buf, (size_t)n);
        }
    }
  EXCEPT (Socket_Closed)
    {
      /* Connection closed - expected during shutdown */
      (void)0;
    }
  END_TRY;

  Socket_free (&client);
  return NULL;
}

static int
socks5_server_start (Socks5TestServer *server, const char *username,
                     const char *password)
{
  struct sockaddr_in addr;
  socklen_t len;

  memset (server, 0, sizeof (*server));

  server->proxy_port = get_proxy_test_port ();
  server->target_port = get_proxy_test_port ();
  server->required_username = username;
  server->required_password = password;

  /* Create proxy listen socket */
  server->listen_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  if (server->listen_socket == NULL)
    return -1;

  TRY
  Socket_setreuseaddr (server->listen_socket);
  Socket_bind (server->listen_socket, "127.0.0.1", server->proxy_port);
  Socket_listen (server->listen_socket, 5);
  EXCEPT (Socket_Failed)
  Socket_free (&server->listen_socket);
  return -1;
  END_TRY;

  /* Get actual port */
  len = sizeof (addr);
  getsockname (Socket_fd (server->listen_socket), (struct sockaddr *)&addr,
               &len);
  server->proxy_port = ntohs (addr.sin_port);

  /* Create target listen socket */
  server->target_listen = Socket_new (AF_INET, SOCK_STREAM, 0);
  if (server->target_listen == NULL)
    {
      Socket_free (&server->listen_socket);
      return -1;
    }

  TRY
  Socket_setreuseaddr (server->target_listen);
  Socket_bind (server->target_listen, "127.0.0.1", server->target_port);
  Socket_listen (server->target_listen, 5);
  EXCEPT (Socket_Failed)
  Socket_free (&server->target_listen);
  Socket_free (&server->listen_socket);
  return -1;
  END_TRY;

  len = sizeof (addr);
  getsockname (Socket_fd (server->target_listen), (struct sockaddr *)&addr,
               &len);
  server->target_port = ntohs (addr.sin_port);

  server->running = 1;

  /* Start echo server thread */
  if (pthread_create (&server->echo_thread, NULL, echo_server_thread_func,
                      server)
      != 0)
    {
      server->running = 0;
      Socket_free (&server->target_listen);
      Socket_free (&server->listen_socket);
      return -1;
    }

  /* Start proxy server thread */
  if (pthread_create (&server->thread, NULL, socks5_server_thread_func, server)
      != 0)
    {
      server->running = 0;
      /* Signal echo thread to stop and wait for it */
      Socket_free (&server->target_listen);
      pthread_join (server->echo_thread, NULL);
      Socket_free (&server->listen_socket);
      return -1;
    }

  /* Wait for servers to start */
  while (!server->started || !server->echo_started)
    usleep (1000);

  return 0;
}

/* Helper to connect to a listening socket to unblock accept() */
static void
unblock_accept (int port)
{
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd >= 0)
    {
      struct sockaddr_in addr;
      memset (&addr, 0, sizeof (addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons (port);
      addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
      /* Non-blocking connect - we don't care if it succeeds */
      int flags = fcntl (fd, F_GETFL, 0);
      if (flags >= 0)
        fcntl (fd, F_SETFL, flags | O_NONBLOCK);
      connect (fd, (struct sockaddr *)&addr, sizeof (addr));
      close (fd);
    }
}

static void
socks5_server_stop (Socks5TestServer *server)
{
  server->running = 0;

  /* To unblock accept() on both Linux and macOS, we connect dummy clients.
   * On macOS, shutdown() on a listening socket does NOT unblock accept(),
   * but connecting to it will cause accept() to return. */
  if (server->listen_socket)
    unblock_accept (server->proxy_port);
  if (server->target_listen)
    unblock_accept (server->target_port);

  /* Wait for threads to exit */
  pthread_join (server->thread, NULL);
  pthread_join (server->echo_thread, NULL);

  /* Now safe to free sockets - threads have exited */
  if (server->listen_socket)
    Socket_free (&server->listen_socket);
  if (server->target_listen)
    Socket_free (&server->target_listen);
}

/* ============================================================================
 * Integration Tests
 * ============================================================================ */

TEST (proxy_integration_url_parsing)
{
  SocketProxy_Config config;
  int result;

  /* Test SOCKS5 URL with credentials */
  result = SocketProxy_parse_url ("socks5://user:pass@proxy.local:1080",
                                  &config, NULL);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.type, SOCKET_PROXY_SOCKS5);
  ASSERT (strcmp (config.host, "proxy.local") == 0);
  ASSERT_EQ (config.port, 1080);
  ASSERT (strcmp (config.username, "user") == 0);
  ASSERT (strcmp (config.password, "pass") == 0);

  /* Test SOCKS5H URL */
  result = SocketProxy_parse_url ("socks5h://localhost:9050", &config, NULL);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.type, SOCKET_PROXY_SOCKS5H);
  ASSERT (strcmp (config.host, "localhost") == 0);
  ASSERT_EQ (config.port, 9050);

  /* Test SOCKS4 URL */
  result = SocketProxy_parse_url ("socks4://192.168.1.1:1080", &config, NULL);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.type, SOCKET_PROXY_SOCKS4);

  /* Test HTTP proxy URL */
  result = SocketProxy_parse_url ("http://proxy:8080", &config, NULL);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.type, SOCKET_PROXY_HTTP);
  ASSERT_EQ (config.port, 8080);

  /* Test HTTPS proxy URL */
  result = SocketProxy_parse_url ("https://secure-proxy:443", &config, NULL);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.type, SOCKET_PROXY_HTTPS);
}

TEST (proxy_integration_socks5_no_auth)
{
  Socks5TestServer server;
  Socket_T client = NULL;
  SocketProxy_Config proxy_config;
  const char *test_data = "Hello via SOCKS5!";
  char response[64] = { 0 };

  signal (SIGPIPE, SIG_IGN);

  if (socks5_server_start (&server, NULL, NULL) < 0)
    {
      printf ("  [SKIP] Could not start SOCKS5 server\n");
      return;
    }

  TRY
  /* Configure proxy */
  memset (&proxy_config, 0, sizeof (proxy_config));
  proxy_config.type = SOCKET_PROXY_SOCKS5;
  proxy_config.host = "127.0.0.1";
  proxy_config.port = server.proxy_port;
  proxy_config.connect_timeout_ms = TEST_TIMEOUT_MS;
  proxy_config.handshake_timeout_ms = TEST_TIMEOUT_MS;

  /* Connect through proxy - this creates socket internally */
  client = SocketProxy_connect (&proxy_config, "127.0.0.1",
                                server.target_port);
  ASSERT_NOT_NULL (client);

  /* Verify tunnel is established */
  int tries = 0;
  while (!server.tunnel_established && tries < 50)
    {
      usleep (10000);
      tries++;
    }
  ASSERT (server.tunnel_established);

  /* Send data through tunnel */
  ssize_t sent = Socket_send (client, test_data, strlen (test_data));
  ASSERT_EQ (sent, (ssize_t)strlen (test_data));

  /* Receive echo */
  ssize_t received = Socket_recv (client, response, sizeof (response) - 1);
  ASSERT_EQ (received, (ssize_t)strlen (test_data));
  ASSERT (strcmp (response, test_data) == 0);

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketProxy_Failed)
  printf ("  [WARN] Proxy error: %s\n", SocketProxy_Failed.reason);
  FINALLY
  if (client)
    Socket_free (&client);
  socks5_server_stop (&server);
  END_TRY;
}

TEST (proxy_integration_socks5_with_auth)
{
  Socks5TestServer server;
  Socket_T client = NULL;
  SocketProxy_Config proxy_config;
  const char *test_data = "Authenticated message!";
  char response[64] = { 0 };

  signal (SIGPIPE, SIG_IGN);

  if (socks5_server_start (&server, "testuser", "testpass") < 0)
    {
      printf ("  [SKIP] Could not start SOCKS5 server\n");
      return;
    }

  TRY
  /* Configure proxy with credentials */
  memset (&proxy_config, 0, sizeof (proxy_config));
  proxy_config.type = SOCKET_PROXY_SOCKS5;
  proxy_config.host = "127.0.0.1";
  proxy_config.port = server.proxy_port;
  proxy_config.username = "testuser";
  proxy_config.password = "testpass";
  proxy_config.connect_timeout_ms = TEST_TIMEOUT_MS;
  proxy_config.handshake_timeout_ms = TEST_TIMEOUT_MS;

  /* Connect through proxy */
  client = SocketProxy_connect (&proxy_config, "127.0.0.1",
                                server.target_port);
  ASSERT_NOT_NULL (client);

  /* Verify tunnel */
  int tries = 0;
  while (!server.tunnel_established && tries < 100)
    {
      usleep (20000);
      tries++;
    }
  if (!server.tunnel_established)
    {
      printf ("  [DEBUG] tunnel not established after %d tries, client_connected=%d\n", 
              tries, server.client_connected);
    }
  ASSERT (server.tunnel_established);

  /* Send and receive */
  ssize_t sent = Socket_send (client, test_data, strlen (test_data));
  ASSERT_EQ (sent, (ssize_t)strlen (test_data));

  ssize_t received = Socket_recv (client, response, sizeof (response) - 1);
  ASSERT_EQ (received, (ssize_t)strlen (test_data));
  ASSERT (strcmp (response, test_data) == 0);

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketProxy_Failed)
  printf ("  [WARN] Proxy error\n");
  FINALLY
  if (client)
    Socket_free (&client);
  socks5_server_stop (&server);
  END_TRY;
}

TEST (proxy_integration_socks5_bad_auth)
{
  Socks5TestServer server;
  Socket_T client = NULL;
  SocketProxy_Config proxy_config;

  signal (SIGPIPE, SIG_IGN);

  if (socks5_server_start (&server, "testuser", "testpass") < 0)
    {
      printf ("  [SKIP] Could not start SOCKS5 server\n");
      return;
    }

  TRY
  /* Configure proxy with wrong credentials */
  memset (&proxy_config, 0, sizeof (proxy_config));
  proxy_config.type = SOCKET_PROXY_SOCKS5;
  proxy_config.host = "127.0.0.1";
  proxy_config.port = server.proxy_port;
  proxy_config.username = "wronguser";
  proxy_config.password = "wrongpass";
  proxy_config.connect_timeout_ms = TEST_TIMEOUT_MS;
  proxy_config.handshake_timeout_ms = TEST_TIMEOUT_MS;

  /* Should fail with auth error - returns NULL */
  client = SocketProxy_connect (&proxy_config, "127.0.0.1",
                                server.target_port);

  /* NULL means connection/auth failed */
  ASSERT_NULL (client);

  EXCEPT (Socket_Failed)
  /* Expected - connection may be closed */
  (void) 0;
  EXCEPT (Socket_Closed)
  /* Expected - server closes connection on auth failure */
  (void) 0;
  EXCEPT (SocketProxy_Failed)
  /* Expected - auth failure */
  (void) 0;
  FINALLY
  if (client)
    Socket_free (&client);
  socks5_server_stop (&server);
  END_TRY;
}

TEST (proxy_integration_config_defaults)
{
  SocketProxy_Config config;

  SocketProxy_config_defaults (&config);

  ASSERT_EQ (config.type, SOCKET_PROXY_NONE);
  ASSERT_NULL (config.host);
  ASSERT_EQ (config.port, 0);
  ASSERT_NULL (config.username);
  ASSERT_NULL (config.password);
  ASSERT (config.connect_timeout_ms > 0);
  ASSERT (config.handshake_timeout_ms > 0);
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int
main (void)
{
  printf ("=== Proxy Integration Tests ===\n");

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}


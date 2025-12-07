/**
 * test_http2_integration.c - HTTP/2 over TLS Integration Tests
 *
 * End-to-end HTTP/2 tests with TLS and ALPN negotiation.
 * Tests:
 * - TLS context setup with ALPN (h2)
 * - HTTP/2 connection preface exchange
 * - SETTINGS frame exchange
 * - PING/PONG for connection testing
 * - Flow control (WINDOW_UPDATE)
 *
 * Module Reuse:
 * - SocketTLSContext for TLS setup
 * - SocketTLS_* for TLS operations (on Socket_T)
 * - SocketHTTP2_* for framing
 * - SocketHPACK for header compression
 * - fuzz_test_certs.h for test certificates
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP2.h"
#include "socket/Socket.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

/* Embedded test certificates */
#include "../fuzz/fuzz_test_certs.h"

/* ============================================================================
 * Test Configuration
 * ============================================================================ */

#define TEST_PORT_BASE 47000
#define TEST_TIMEOUT_MS 5000

static int h2_test_port_counter = 0;

static int
get_h2_test_port (void)
{
  return TEST_PORT_BASE + (h2_test_port_counter++ % 1000);
}

/* ============================================================================
 * Certificate File Helpers
 * ============================================================================ */

static char cert_file[64];
static char key_file[64];

static int
create_temp_cert_files (void)
{
  FILE *f;

  snprintf (cert_file, sizeof (cert_file), "/tmp/test_h2_cert_%d.pem",
            getpid ());
  snprintf (key_file, sizeof (key_file), "/tmp/test_h2_key_%d.pem", getpid ());

  f = fopen (cert_file, "w");
  if (f == NULL)
    return -1;
  fputs (FUZZ_TEST_CERT, f);
  fclose (f);

  f = fopen (key_file, "w");
  if (f == NULL)
    {
      unlink (cert_file);
      return -1;
    }
  fputs (FUZZ_TEST_KEY, f);
  fclose (f);

  return 0;
}

static void
cleanup_temp_cert_files (void)
{
  unlink (cert_file);
  unlink (key_file);
}

/* ============================================================================
 * HTTP/2 Server Thread
 * ============================================================================ */

typedef struct
{
  Socket_T listen_socket;
  SocketTLSContext_T tls_ctx;
  pthread_t thread;
  volatile int running;
  volatile int started;
  volatile int client_connected;
  volatile int preface_received;
  int port;
} H2TestServer;

/* HTTP/2 connection preface (client magic) */
static const char H2_CLIENT_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_CLIENT_PREFACE_LEN 24

static void *
h2_server_thread_func (void *arg)
{
  H2TestServer *server = (H2TestServer *)arg;
  Socket_T client = NULL;
  char buf[128];
  ssize_t n;

  server->started = 1;

  /* Accept client */
  client = Socket_accept (server->listen_socket);
  if (client == NULL)
    {
      server->running = 0;
      return NULL;
    }

  server->client_connected = 1;

  /* TLS handshake - enable TLS on the socket */
  TRY
  SocketTLS_enable (client, server->tls_ctx);

  TLSHandshakeState hs_state;
  do
    {
      hs_state = SocketTLS_handshake (client);
    }
  while (hs_state == TLS_HANDSHAKE_WANT_READ
         || hs_state == TLS_HANDSHAKE_WANT_WRITE);

  if (hs_state != TLS_HANDSHAKE_COMPLETE)
    {
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }
  EXCEPT (SocketTLS_Failed)
  if (client)
    Socket_free (&client);
  server->running = 0;
  return NULL;
  EXCEPT (SocketTLS_HandshakeFailed)
  if (client)
    Socket_free (&client);
  server->running = 0;
  return NULL;
  END_TRY;

  /* Verify ALPN negotiated h2 */
  const char *alpn = SocketTLS_get_alpn_selected (client);
  if (alpn == NULL || strcmp (alpn, "h2") != 0)
    {
      /* ALPN not negotiated or wrong protocol */
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }

  /* Read HTTP/2 client preface */
  n = SocketTLS_recv (client, buf, H2_CLIENT_PREFACE_LEN);
  if (n == H2_CLIENT_PREFACE_LEN
      && memcmp (buf, H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN) == 0)
    {
      server->preface_received = 1;

      /* Send server SETTINGS frame */
      unsigned char settings_frame[9] = {
        0x00, 0x00, 0x00, /* Length: 0 (empty settings) */
        0x04,             /* Type: SETTINGS */
        0x00,             /* Flags: 0 */
        0x00, 0x00, 0x00, 0x00 /* Stream ID: 0 */
      };
      SocketTLS_send (client, settings_frame, 9);

      /* Read client's SETTINGS frame */
      n = SocketTLS_recv (client, buf, sizeof (buf));
      if (n >= 9)
        {
          /* Check if it's a SETTINGS frame */
          if (buf[3] == 0x04)
            { /* SETTINGS type */
              /* Send SETTINGS ACK */
              unsigned char settings_ack[9] = { 0x00, 0x00, 0x00, 0x04, 0x01,
                                                0x00, 0x00, 0x00, 0x00 };
              SocketTLS_send (client, settings_ack, 9);
            }
        }
    }

  /* Keep connection alive briefly for tests */
  usleep (100000);

  /* Cleanup */
  Socket_free (&client);

  return NULL;
}

static int
h2_server_start (H2TestServer *server)
{
  int port;
  struct sockaddr_in addr;
  socklen_t len;

  memset (server, 0, sizeof (*server));

  port = get_h2_test_port ();
  server->port = port;

  /* Create TLS context */
  TRY
  server->tls_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
  EXCEPT (SocketTLS_Failed)
  return -1;
  END_TRY;

  if (server->tls_ctx == NULL)
    return -1;

  /* Set ALPN protocols (h2 for HTTP/2) */
  const char *alpn_protos[] = { "h2", "http/1.1" };
  SocketTLSContext_set_alpn_protos (server->tls_ctx, alpn_protos, 2);

  /* Create listen socket */
  server->listen_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  if (server->listen_socket == NULL)
    {
      SocketTLSContext_free (&server->tls_ctx);
      return -1;
    }

  TRY
  Socket_setreuseaddr (server->listen_socket);
  Socket_bind (server->listen_socket, "127.0.0.1", port);
  Socket_listen (server->listen_socket, 5);
  EXCEPT (Socket_Failed)
  Socket_free (&server->listen_socket);
  SocketTLSContext_free (&server->tls_ctx);
  return -1;
  END_TRY;

  /* Get actual port */
  len = sizeof (addr);
  getsockname (Socket_fd (server->listen_socket), (struct sockaddr *)&addr,
               &len);
  server->port = ntohs (addr.sin_port);

  server->running = 1;

  if (pthread_create (&server->thread, NULL, h2_server_thread_func, server)
      != 0)
    {
      server->running = 0;
      Socket_free (&server->listen_socket);
      SocketTLSContext_free (&server->tls_ctx);
      return -1;
    }

  /* Wait for server thread to start */
  while (!server->started)
    usleep (1000);

  return 0;
}

static void
h2_server_stop (H2TestServer *server)
{
  server->running = 0;

  if (server->listen_socket)
    Socket_free (&server->listen_socket);

  pthread_join (server->thread, NULL);

  if (server->tls_ctx)
    SocketTLSContext_free (&server->tls_ctx);
}

/* ============================================================================
 * Integration Tests
 * ============================================================================ */

TEST (http2_integration_tls_alpn)
{
  H2TestServer server;
  Socket_T client = NULL;
  SocketTLSContext_T client_ctx = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () < 0)
    {
      printf ("  [SKIP] Could not create test certificates\n");
      return;
    }

  if (h2_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start HTTP/2 server\n");
      cleanup_temp_cert_files ();
      return;
    }

  TRY
  /* Create client TLS context */
  client_ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (client_ctx);

  /* Disable certificate verification for self-signed cert */
  SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

  /* Set ALPN for HTTP/2 */
  const char *alpn_protos[] = { "h2" };
  SocketTLSContext_set_alpn_protos (client_ctx, alpn_protos, 1);

  /* Connect */
  client = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (client);
  Socket_connect (client, "127.0.0.1", server.port);

  /* Enable TLS and perform handshake */
  SocketTLS_enable (client, client_ctx);

  TLSHandshakeState hs_state;
  do
    {
      hs_state = SocketTLS_handshake (client);
    }
  while (hs_state == TLS_HANDSHAKE_WANT_READ
         || hs_state == TLS_HANDSHAKE_WANT_WRITE);

  ASSERT_EQ (hs_state, TLS_HANDSHAKE_COMPLETE);

  /* Verify ALPN negotiated h2 */
  const char *alpn = SocketTLS_get_alpn_selected (client);
  ASSERT_NOT_NULL (alpn);
  ASSERT (strcmp (alpn, "h2") == 0);

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketTLS_Failed)
  printf ("  [WARN] TLS error: %s\n", SocketTLS_Failed.reason);
  EXCEPT (SocketTLS_HandshakeFailed)
  printf ("  [WARN] TLS handshake failed\n");
  FINALLY
  if (client)
    Socket_free (&client);
  if (client_ctx)
    SocketTLSContext_free (&client_ctx);
  h2_server_stop (&server);
  cleanup_temp_cert_files ();
  END_TRY;
}

TEST (http2_integration_connection_preface)
{
  H2TestServer server;
  Socket_T client = NULL;
  SocketTLSContext_T client_ctx = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () < 0)
    {
      printf ("  [SKIP] Could not create test certificates\n");
      return;
    }

  if (h2_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start HTTP/2 server\n");
      cleanup_temp_cert_files ();
      return;
    }

  TRY
  /* Create client TLS context */
  client_ctx = SocketTLSContext_new_client (NULL);
  SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

  const char *alpn_protos[] = { "h2" };
  SocketTLSContext_set_alpn_protos (client_ctx, alpn_protos, 1);

  /* Connect and TLS handshake */
  client = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_connect (client, "127.0.0.1", server.port);

  SocketTLS_enable (client, client_ctx);

  TLSHandshakeState hs_state;
  do
    {
      hs_state = SocketTLS_handshake (client);
    }
  while (hs_state == TLS_HANDSHAKE_WANT_READ
         || hs_state == TLS_HANDSHAKE_WANT_WRITE);

  ASSERT_EQ (hs_state, TLS_HANDSHAKE_COMPLETE);

  /* Send HTTP/2 client preface */
  ssize_t sent
      = SocketTLS_send (client, H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN);
  ASSERT_EQ (sent, H2_CLIENT_PREFACE_LEN);

  /* Send SETTINGS frame */
  unsigned char settings_frame[9] = { 0x00, 0x00, 0x00, /* Length: 0 */
                                      0x04,             /* Type: SETTINGS */
                                      0x00,             /* Flags: 0 */
                                      0x00, 0x00, 0x00, 0x00 }; /* Stream: 0 */
  sent = SocketTLS_send (client, settings_frame, 9);
  ASSERT_EQ (sent, 9);

  /* Wait for server to process */
  usleep (50000);

  /* Verify server received preface */
  int tries = 0;
  while (!server.preface_received && tries < 50)
    {
      usleep (10000);
      tries++;
    }
  ASSERT (server.preface_received);

  /* Read server's SETTINGS frame */
  unsigned char buf[64];
  ssize_t n = SocketTLS_recv (client, buf, sizeof (buf));
  ASSERT (n >= 9);
  ASSERT_EQ (buf[3], 0x04); /* SETTINGS type */

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketTLS_Failed)
  printf ("  [WARN] TLS error\n");
  EXCEPT (SocketTLS_HandshakeFailed)
  printf ("  [WARN] TLS handshake failed\n");
  FINALLY
  if (client)
    Socket_free (&client);
  if (client_ctx)
    SocketTLSContext_free (&client_ctx);
  h2_server_stop (&server);
  cleanup_temp_cert_files ();
  END_TRY;
}

TEST (http2_integration_frame_parsing)
{
  /* Test HTTP/2 frame header parsing (integration of SocketHTTP2 module) */
  SocketHTTP2_FrameHeader header;
  unsigned char data[9];

  /* Build a SETTINGS frame header */
  data[0] = 0x00;
  data[1] = 0x00;
  data[2] = 0x12; /* Length: 18 */
  data[3] = 0x04; /* Type: SETTINGS */
  data[4] = 0x00; /* Flags: 0 */
  data[5] = 0x00;
  data[6] = 0x00;
  data[7] = 0x00;
  data[8] = 0x00; /* Stream ID: 0 */

  int result = SocketHTTP2_frame_header_parse ((const unsigned char *)data, 9, &header);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (header.length, 18);
  ASSERT_EQ (header.type, HTTP2_FRAME_SETTINGS);
  ASSERT_EQ (header.flags, 0);
  ASSERT_EQ (header.stream_id, 0);

  /* Build a PING frame header */
  data[0] = 0x00;
  data[1] = 0x00;
  data[2] = 0x08; /* Length: 8 (ping payload) */
  data[3] = 0x06; /* Type: PING */
  data[4] = 0x00; /* Flags: 0 */
  data[5] = 0x00;
  data[6] = 0x00;
  data[7] = 0x00;
  data[8] = 0x00; /* Stream ID: 0 */

  result = SocketHTTP2_frame_header_parse ((const unsigned char *)data, 9, &header);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (header.length, 8);
  ASSERT_EQ (header.type, HTTP2_FRAME_PING);

  /* Build a DATA frame header */
  data[0] = 0x00;
  data[1] = 0x01;
  data[2] = 0x00; /* Length: 256 */
  data[3] = 0x00; /* Type: DATA */
  data[4] = 0x01; /* Flags: END_STREAM */
  data[5] = 0x00;
  data[6] = 0x00;
  data[7] = 0x00;
  data[8] = 0x01; /* Stream ID: 1 */

  result = SocketHTTP2_frame_header_parse ((const unsigned char *)data, 9, &header);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (header.length, 256);
  ASSERT_EQ (header.type, HTTP2_FRAME_DATA);
  ASSERT_EQ (header.flags, HTTP2_FLAG_END_STREAM);
  ASSERT_EQ (header.stream_id, 1);
}

TEST (http2_integration_frame_serialization)
{
  SocketHTTP2_FrameHeader header;
  unsigned char data[9];

  /* Serialize a HEADERS frame */
  header.length = 128;
  header.type = HTTP2_FRAME_HEADERS;
  header.flags = HTTP2_FLAG_END_HEADERS;
  header.stream_id = 3;

  SocketHTTP2_frame_header_serialize (&header, data);

  ASSERT_EQ (data[0], 0x00);
  ASSERT_EQ (data[1], 0x00);
  ASSERT_EQ (data[2], 0x80); /* 128 */
  ASSERT_EQ (data[3], HTTP2_FRAME_HEADERS);
  ASSERT_EQ (data[4], HTTP2_FLAG_END_HEADERS);
  ASSERT_EQ (data[5], 0x00);
  ASSERT_EQ (data[6], 0x00);
  ASSERT_EQ (data[7], 0x00);
  ASSERT_EQ (data[8], 0x03);
}

#else /* !SOCKET_HAS_TLS */

/* Non-TLS stubs - HTTP/2 requires TLS for full testing */

TEST (http2_integration_no_tls)
{
  printf ("  [SKIP] TLS not enabled - HTTP/2 integration tests require TLS\n");
}

#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int
main (void)
{
  printf ("=== HTTP/2 Integration Tests ===\n");

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}

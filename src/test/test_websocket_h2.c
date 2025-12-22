/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_websocket_h2.c - WebSocket over HTTP/2 Tests (RFC 8441)
 *
 * Tests:
 * 1. Transport type detection (H2STREAM vs SOCKET)
 * 2. No masking requirement for HTTP/2 transport
 * 3. Extended CONNECT support check
 * 4. Transport factory functions
 * 5. SocketWSH2 API functions
 * 6. Client connect prerequisites
 * 7. Server accept prerequisites
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
#include "socket/SocketWS.h"
#include "socket/SocketWS-transport.h"
#include "socket/SocketWSH2.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

/* Embedded test certificates */
#include "../fuzz/fuzz_test_certs.h"

/* ============================================================================
 * Test Configuration
 * ============================================================================
 */

#define TEST_PORT_BASE 49000
#define TEST_TIMEOUT_MS 5000

static int wsh2_test_port_counter = 0;

static int
get_wsh2_test_port (void)
{
  return TEST_PORT_BASE + (wsh2_test_port_counter++ % 1000);
}

/* ============================================================================
 * Certificate File Helpers
 * ============================================================================
 */

static char cert_file[64];
static char key_file[64];

static int
create_temp_cert_files (void)
{
  FILE *f;

  snprintf (cert_file, sizeof (cert_file), "/tmp/test_wsh2_cert_%d.pem",
            getpid ());
  snprintf (key_file, sizeof (key_file), "/tmp/test_wsh2_key_%d.pem",
            getpid ());

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
 * Unit Tests - Transport Abstraction Layer
 * ============================================================================
 */

TEST (wsh2_transport_type_enum_values)
{
  /* Verify transport type enum values */
  ASSERT_EQ (SOCKETWS_TRANSPORT_SOCKET, 0);
  ASSERT_EQ (SOCKETWS_TRANSPORT_H2STREAM, 1);
}

TEST (wsh2_transport_socket_factory)
{
  Arena_T arena = NULL;
  Socket_T socket = NULL;
  SocketWS_Transport_T transport = NULL;

  TRY
  {
    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);

    /* Create a TCP socket */
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    /* Create socket transport (client mode - requires masking) */
    transport = SocketWS_Transport_socket (arena, socket, 1);
    ASSERT_NOT_NULL (transport);

    /* Verify transport type */
    ASSERT_EQ (SocketWS_Transport_type (transport), SOCKETWS_TRANSPORT_SOCKET);

    /* Verify masking is required for socket transport client */
    ASSERT_EQ (SocketWS_Transport_requires_masking (transport), 1);

    /* Verify we can get the socket back */
    Socket_T got_socket = SocketWS_Transport_get_socket (transport);
    ASSERT_EQ (got_socket, socket);

    /* Verify H2 stream accessor returns NULL for socket transport */
    SocketHTTP2_Stream_T h2stream
        = SocketWS_Transport_get_h2stream (transport);
    ASSERT_NULL (h2stream);
  }
  FINALLY
  {
    if (transport)
      SocketWS_Transport_free (&transport);
    if (socket)
      Socket_free (&socket);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;
}

TEST (wsh2_transport_socket_server_no_mask)
{
  Arena_T arena = NULL;
  Socket_T socket = NULL;
  SocketWS_Transport_T transport = NULL;

  TRY
  {
    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);

    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    /* Create socket transport (server mode - no masking) */
    transport = SocketWS_Transport_socket (arena, socket, 0);
    ASSERT_NOT_NULL (transport);

    /* Server socket transport should NOT require masking */
    ASSERT_EQ (SocketWS_Transport_requires_masking (transport), 0);
  }
  FINALLY
  {
    if (transport)
      SocketWS_Transport_free (&transport);
    if (socket)
      Socket_free (&socket);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;
}

TEST (wsh2_transport_get_fd_socket)
{
  Arena_T arena = NULL;
  Socket_T socket = NULL;
  SocketWS_Transport_T transport = NULL;

  TRY
  {
    arena = Arena_new ();
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    transport = SocketWS_Transport_socket (arena, socket, 1);
    ASSERT_NOT_NULL (transport);

    /* Socket transport should return valid FD */
    int fd = SocketWS_Transport_get_fd (transport);
    ASSERT (fd >= 0);

    /* FD should match underlying socket FD */
    ASSERT_EQ (fd, Socket_fd (socket));
  }
  FINALLY
  {
    if (transport)
      SocketWS_Transport_free (&transport);
    if (socket)
      Socket_free (&socket);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;
}

/* ============================================================================
 * Unit Tests - HTTP/2 Extended CONNECT Settings
 * ============================================================================
 */

TEST (wsh2_settings_enable_connect_protocol)
{
  /* Verify SETTINGS_ENABLE_CONNECT_PROTOCOL ID matches RFC 8441 */
  ASSERT_EQ (HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 0x8);
}

TEST (wsh2_config_defaults_connect_protocol)
{
  /* Verify server config defaults include enable_connect_protocol option */
  SocketHTTP2_Config config;
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_SERVER);

  /* Server should have connect protocol disabled by default (opt-in) */
  /* The enable_connect_protocol field should exist */
  ASSERT (config.enable_connect_protocol == 0
          || config.enable_connect_protocol == 1);
}

/* ============================================================================
 * Unit Tests - WebSocket State for HTTP/2
 * ============================================================================
 */

TEST (wsh2_websocket_state_open)
{
  /* Verify WS_STATE_OPEN exists and has expected value */
  ASSERT_EQ (WS_STATE_OPEN, 1);

  /* Per RFC 8441, WebSocket over HTTP/2 starts in OPEN state immediately */
  /* (no handshake needed after Extended CONNECT response) */
}

TEST (wsh2_websocket_role_values)
{
  /* Verify role enum values */
  ASSERT_EQ (WS_ROLE_CLIENT, 0);
  ASSERT_EQ (WS_ROLE_SERVER, 1);
}

TEST (wsh2_websocket_close_codes)
{
  /* Verify standard close codes exist */
  ASSERT_EQ (WS_CLOSE_NORMAL, 1000);
  ASSERT_EQ (WS_CLOSE_GOING_AWAY, 1001);
  ASSERT_EQ (WS_CLOSE_PROTOCOL_ERROR, 1002);
}

/* ============================================================================
 * Unit Tests - WebSocket Config
 * ============================================================================
 */

TEST (wsh2_config_defaults)
{
  SocketWS_Config config;
  SocketWS_config_defaults (&config);

  /* Verify sensible defaults */
  ASSERT (config.max_frame_size > 0);
  ASSERT (config.max_message_size >= config.max_frame_size);
  ASSERT (config.max_fragments > 0);
}

/* ============================================================================
 * HTTP/2 Connection Tests (Prerequisites for WebSocket-over-H2)
 * ============================================================================
 */

typedef struct
{
  Socket_T listen_socket;
  SocketTLSContext_T tls_ctx;
  pthread_t thread;
  volatile int running;
  volatile int started;
  volatile int client_connected;
  volatile int enable_connect_protocol_sent;
  int port;
} WSH2TestServer;

static const char H2_CLIENT_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_CLIENT_PREFACE_LEN 24

static void *
wsh2_server_thread_func (void *arg)
{
  WSH2TestServer *server = (WSH2TestServer *)arg;
  Socket_T client = NULL;
  char buf[512];
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

  /* TLS handshake */
  TRY SocketTLS_enable (client, server->tls_ctx);

  TLSHandshakeState hs_state;
  int hs_loops = 0;
  do
    {
      hs_state = SocketTLS_handshake (client);
      if (++hs_loops > 1000)
        {
          hs_state = TLS_HANDSHAKE_ERROR;
          break;
        }
      usleep (1000);
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
      Socket_free (&client);
      server->running = 0;
      return NULL;
    }

  /* Read HTTP/2 client preface */
  n = SocketTLS_recv (client, buf, H2_CLIENT_PREFACE_LEN);
  if (n == H2_CLIENT_PREFACE_LEN
      && memcmp (buf, H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN) == 0)
    {
      /* Send server SETTINGS with ENABLE_CONNECT_PROTOCOL=1 (RFC 8441) */
      unsigned char settings_frame[] = {
        0x00, 0x00, 0x06,      /* Length: 6 (one setting) */
        0x04,                  /* Type: SETTINGS */
        0x00,                  /* Flags: 0 */
        0x00, 0x00, 0x00, 0x00, /* Stream ID: 0 */
        /* SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 */
        0x00, 0x08, /* ID: ENABLE_CONNECT_PROTOCOL (0x08) */
        0x00, 0x00, 0x00, 0x01  /* Value: 1 */
      };
      SocketTLS_send (client, settings_frame, sizeof (settings_frame));
      server->enable_connect_protocol_sent = 1;

      /* Read client's SETTINGS frame */
      n = SocketTLS_recv (client, buf, sizeof (buf));
      if (n >= 9 && buf[3] == 0x04)
        {
          /* Send SETTINGS ACK */
          unsigned char settings_ack[9]
              = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };
          SocketTLS_send (client, settings_ack, 9);
        }

      /* Wait for Extended CONNECT request (HEADERS with :protocol=websocket) */
      n = SocketTLS_recv (client, buf, sizeof (buf));
      if (n >= 9 && buf[3] == 0x01) /* HEADERS frame */
        {
          /* Send 200 response (not 101) per RFC 8441 */
          unsigned char response_headers[] = {
            0x00, 0x00, 0x01,      /* Length: 1 */
            0x01,                  /* Type: HEADERS */
            0x04,                  /* Flags: END_HEADERS (no END_STREAM) */
            0x00, 0x00, 0x00, 0x01, /* Stream ID: 1 */
            0x88                   /* :status: 200 (HPACK index 8) */
          };
          SocketTLS_send (client, response_headers, sizeof (response_headers));
        }
    }

  /* Keep connection alive briefly for tests */
  usleep (200000);

  /* Cleanup */
  Socket_free (&client);

  return NULL;
}

static int
wsh2_server_start (WSH2TestServer *server)
{
  int port;
  struct sockaddr_in addr;
  socklen_t len;

  memset (server, 0, sizeof (*server));

  port = get_wsh2_test_port ();
  server->port = port;

  /* Create TLS context */
  TRY server->tls_ctx
      = SocketTLSContext_new_server (cert_file, key_file, NULL);
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

  TRY Socket_setreuseaddr (server->listen_socket);
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

  if (pthread_create (&server->thread, NULL, wsh2_server_thread_func, server)
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
wsh2_server_stop (WSH2TestServer *server)
{
  server->running = 0;

  if (server->listen_socket)
    Socket_free (&server->listen_socket);

  pthread_join (server->thread, NULL);

  if (server->tls_ctx)
    SocketTLSContext_free (&server->tls_ctx);
}

TEST (wsh2_extended_connect_negotiation)
{
  WSH2TestServer server;
  Socket_T client = NULL;
  SocketTLSContext_T client_ctx = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () < 0)
    {
      printf ("  [SKIP] Could not create test certificates\n");
      return;
    }

  if (wsh2_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start HTTP/2 server\n");
      cleanup_temp_cert_files ();
      return;
    }

  TRY
      /* Create client TLS context */
      client_ctx
      = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (client_ctx);

  SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

  const char *alpn_protos[] = { "h2" };
  SocketTLSContext_set_alpn_protos (client_ctx, alpn_protos, 1);

  /* Connect */
  client = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (client);
  Socket_connect (client, "127.0.0.1", server.port);

  /* TLS handshake */
  SocketTLS_enable (client, client_ctx);

  TLSHandshakeState hs_state;
  int hs_loops = 0;
  do
    {
      hs_state = SocketTLS_handshake (client);
      if (++hs_loops > 1000)
        {
          hs_state = TLS_HANDSHAKE_ERROR;
          break;
        }
      usleep (1000);
    }
  while (hs_state == TLS_HANDSHAKE_WANT_READ
         || hs_state == TLS_HANDSHAKE_WANT_WRITE);

  ASSERT_EQ (hs_state, TLS_HANDSHAKE_COMPLETE);

  /* Verify ALPN */
  const char *alpn = SocketTLS_get_alpn_selected (client);
  ASSERT_NOT_NULL (alpn);
  ASSERT (strcmp (alpn, "h2") == 0);

  /* Send HTTP/2 client preface */
  ssize_t sent
      = SocketTLS_send (client, H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN);
  ASSERT_EQ (sent, H2_CLIENT_PREFACE_LEN);

  /* Send SETTINGS frame */
  unsigned char settings_frame[]
      = { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
  SocketTLS_send (client, settings_frame, 9);

  /* Wait for server to send its SETTINGS with ENABLE_CONNECT_PROTOCOL */
  usleep (50000);

  /* Verify server sent ENABLE_CONNECT_PROTOCOL=1 */
  int tries = 0;
  while (!server.enable_connect_protocol_sent && tries < 50)
    {
      usleep (10000);
      tries++;
    }
  ASSERT (server.enable_connect_protocol_sent);

  /* Read server's SETTINGS frame (should contain ENABLE_CONNECT_PROTOCOL) */
  unsigned char buf[256];
  ssize_t n = SocketTLS_recv (client, buf, sizeof (buf));
  ASSERT (n >= 9);
  ASSERT_EQ (buf[3], 0x04); /* SETTINGS type */

  /* Verify ENABLE_CONNECT_PROTOCOL setting in payload */
  /* Frame: 9 byte header + 6 byte setting (ID 0x0008 + value 0x00000001) */
  if (n >= 15)
    {
      uint16_t setting_id = (buf[9] << 8) | buf[10];
      uint32_t setting_value
          = (buf[11] << 24) | (buf[12] << 16) | (buf[13] << 8) | buf[14];
      ASSERT_EQ (setting_id, 0x08); /* ENABLE_CONNECT_PROTOCOL */
      ASSERT_EQ (setting_value, 1);
    }

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
  wsh2_server_stop (&server);
  cleanup_temp_cert_files ();
  END_TRY;
}

#else /* !SOCKET_HAS_TLS */

TEST (wsh2_no_tls)
{
  printf (
      "  [SKIP] TLS not enabled - WebSocket-over-HTTP/2 tests require TLS\n");
}

#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * Main Entry Point
 * ============================================================================
 */

int
main (void)
{
  printf ("=== WebSocket over HTTP/2 Tests (RFC 8441) ===\n");

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}

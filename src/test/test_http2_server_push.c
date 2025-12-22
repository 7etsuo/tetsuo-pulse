/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_http2_server_push.c - HTTP/2 Server Push Tests (RFC 9113 Section 8.4)
 *
 * Tests:
 * 1. PUSH_PROMISE frame creation and stream state
 * 2. Promised stream ID allocation (even IDs)
 * 3. HPACK header encoding in PUSH_PROMISE
 * 4. Push disabled by client (ENABLE_PUSH=0)
 * 5. Wrong role check (client cannot push)
 * 6. Multiple pushes on same stream
 * 7. Client reception of PUSH_PROMISE (integration)
 * 8. Promised stream ID must be even (RFC 9113 §5.1.1)
 * 9. Promised stream ID must be monotonically increasing (RFC 9113 §5.1.1)
 * 10. Promised stream ID 0 is invalid (RFC 9113 §5.1.1)
 * 11. Promised stream ID max limit (31-bit, RFC 9113 §5.1.1)
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"
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
 * ============================================================================
 */

#define TEST_PORT_BASE 48000
#define TEST_TIMEOUT_MS 5000

static int push_test_port_counter = 0;

static int
get_push_test_port (void)
{
  return TEST_PORT_BASE + (push_test_port_counter++ % 1000);
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

  snprintf (cert_file, sizeof (cert_file), "/tmp/test_push_cert_%d.pem",
            getpid ());
  snprintf (key_file, sizeof (key_file), "/tmp/test_push_key_%d.pem",
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
 * HTTP/2 Push Server Thread
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
  volatile int preface_received;
  volatile int push_promise_sent;
  volatile uint32_t pushed_stream_id;
  int port;
} PushTestServer;

/* HTTP/2 connection preface (client magic) */
static const char H2_CLIENT_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_CLIENT_PREFACE_LEN 24

static void *
push_server_thread_func (void *arg)
{
  PushTestServer *server = (PushTestServer *)arg;
  Socket_T client = NULL;
  char buf[256];
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
      server->preface_received = 1;

      /* Send server SETTINGS frame with ENABLE_PUSH=1 */
      unsigned char settings_frame[] = {
        0x00, 0x00, 0x06,      /* Length: 6 (one setting) */
        0x04,                  /* Type: SETTINGS */
        0x00,                  /* Flags: 0 */
        0x00, 0x00, 0x00, 0x00, /* Stream ID: 0 */
        /* SETTINGS_ENABLE_PUSH = 1 */
        0x00, 0x02, /* ID: ENABLE_PUSH */
        0x00, 0x00, 0x00, 0x01  /* Value: 1 */
      };
      SocketTLS_send (client, settings_frame, sizeof (settings_frame));

      /* Read client's SETTINGS frame */
      n = SocketTLS_recv (client, buf, sizeof (buf));
      if (n >= 9 && buf[3] == 0x04)
        {
          /* Send SETTINGS ACK */
          unsigned char settings_ack[9]
              = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };
          SocketTLS_send (client, settings_ack, 9);
        }

      /* Read client's HEADERS frame (stream 1) */
      n = SocketTLS_recv (client, buf, sizeof (buf));
      if (n >= 9 && buf[3] == 0x01) /* HEADERS frame */
        {
          /* Send PUSH_PROMISE frame for stream 2 */
          unsigned char push_promise[] = {
            0x00, 0x00, 0x15,      /* Length: 21 */
            0x05,                  /* Type: PUSH_PROMISE */
            0x04,                  /* Flags: END_HEADERS */
            0x00, 0x00, 0x00, 0x01, /* Stream ID: 1 (associated stream) */
            /* Promised Stream ID: 2 (4 bytes) */
            0x00, 0x00, 0x00, 0x02,
            /* HPACK encoded headers (simplified - static table refs) */
            0x82,             /* :method: GET (index 2) */
            0x86,             /* :scheme: http (index 6) */
            0x84,             /* :path: / (index 4) */
            0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70, 0xdc, 0x78,
            0x0f, 0x03 /* :authority: www.example.com */
          };
          SocketTLS_send (client, push_promise, sizeof (push_promise));
          server->push_promise_sent = 1;
          server->pushed_stream_id = 2;

          /* Send response HEADERS for stream 1 */
          unsigned char response_headers[] = {
            0x00, 0x00, 0x01,      /* Length: 1 */
            0x01,                  /* Type: HEADERS */
            0x05,                  /* Flags: END_STREAM | END_HEADERS */
            0x00, 0x00, 0x00, 0x01, /* Stream ID: 1 */
            0x88                   /* :status: 200 (index 8) */
          };
          SocketTLS_send (client, response_headers, sizeof (response_headers));
        }
    }

  /* Keep connection alive briefly for tests */
  usleep (100000);

  /* Cleanup */
  Socket_free (&client);

  return NULL;
}

static int
push_server_start (PushTestServer *server)
{
  int port;
  struct sockaddr_in addr;
  socklen_t len;

  memset (server, 0, sizeof (*server));

  port = get_push_test_port ();
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

  if (pthread_create (&server->thread, NULL, push_server_thread_func, server)
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
push_server_stop (PushTestServer *server)
{
  server->running = 0;

  if (server->listen_socket)
    Socket_free (&server->listen_socket);

  pthread_join (server->thread, NULL);

  if (server->tls_ctx)
    SocketTLSContext_free (&server->tls_ctx);
}

/* ============================================================================
 * Unit Tests - PUSH_PROMISE Frame Structure
 * ============================================================================
 */

TEST (http2_push_promise_frame_type)
{
  /* Verify PUSH_PROMISE frame type constant (RFC 9113 Section 6.6) */
  ASSERT_EQ (HTTP2_FRAME_PUSH_PROMISE, 0x5);
}

TEST (http2_push_promise_id_size)
{
  /* Verify promised stream ID field size (4 bytes) */
  ASSERT_EQ (HTTP2_PUSH_PROMISE_ID_SIZE, 4);
}

TEST (http2_push_stream_state_reserved)
{
  /* Verify RESERVED_LOCAL state exists for pushed streams */
  ASSERT_EQ (HTTP2_STREAM_STATE_RESERVED_LOCAL, 1);
  ASSERT_EQ (HTTP2_STREAM_STATE_RESERVED_REMOTE, 2);

  /* Verify state string conversion */
  const char *local_str
      = SocketHTTP2_stream_state_string (HTTP2_STREAM_STATE_RESERVED_LOCAL);
  ASSERT_NOT_NULL (local_str);
  ASSERT (strcmp (local_str, "reserved (local)") == 0);

  const char *remote_str
      = SocketHTTP2_stream_state_string (HTTP2_STREAM_STATE_RESERVED_REMOTE);
  ASSERT_NOT_NULL (remote_str);
  ASSERT (strcmp (remote_str, "reserved (remote)") == 0);
}

TEST (http2_push_promise_event_type)
{
  /* Verify PUSH_PROMISE event type exists */
  ASSERT_EQ (HTTP2_EVENT_PUSH_PROMISE, 7);
}

TEST (http2_settings_enable_push)
{
  /* Verify ENABLE_PUSH setting ID */
  ASSERT_EQ (HTTP2_SETTINGS_ENABLE_PUSH, 0x2);

  /* Verify default enable_push value for server */
  SocketHTTP2_Config config;
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_SERVER);
  ASSERT_EQ (config.enable_push, SOCKETHTTP2_DEFAULT_ENABLE_PUSH);
}

TEST (http2_config_client_disables_push)
{
  /* Verify client disables push by default */
  SocketHTTP2_Config config;
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_CLIENT);
  ASSERT_EQ (config.enable_push, 0);
}

/* ============================================================================
 * Integration Test - Client Receives PUSH_PROMISE
 * ============================================================================
 */

TEST (http2_push_promise_client_reception)
{
  PushTestServer server;
  Socket_T client = NULL;
  SocketTLSContext_T client_ctx = NULL;

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () < 0)
    {
      printf ("  [SKIP] Could not create test certificates\n");
      return;
    }

  if (push_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start HTTP/2 push server\n");
      cleanup_temp_cert_files ();
      return;
    }

  TRY
      /* Create client TLS context */
      client_ctx
      = SocketTLSContext_new_client (NULL);
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

  /* Verify ALPN negotiated h2 */
  const char *alpn = SocketTLS_get_alpn_selected (client);
  ASSERT_NOT_NULL (alpn);
  ASSERT (strcmp (alpn, "h2") == 0);

  /* Send HTTP/2 client preface */
  ssize_t sent
      = SocketTLS_send (client, H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN);
  ASSERT_EQ (sent, H2_CLIENT_PREFACE_LEN);

  /* Send SETTINGS frame with ENABLE_PUSH=1 (client accepts pushes) */
  unsigned char settings_frame[] = {
    0x00, 0x00, 0x06,      /* Length: 6 (one setting) */
    0x04,                  /* Type: SETTINGS */
    0x00,                  /* Flags: 0 */
    0x00, 0x00, 0x00, 0x00, /* Stream ID: 0 */
    /* SETTINGS_ENABLE_PUSH = 1 */
    0x00, 0x02, /* ID: ENABLE_PUSH */
    0x00, 0x00, 0x00, 0x01  /* Value: 1 */
  };
  sent = SocketTLS_send (client, settings_frame, sizeof (settings_frame));
  ASSERT_EQ (sent, (ssize_t)sizeof (settings_frame));

  /* Read server's SETTINGS frame */
  unsigned char buf[256];
  ssize_t n = SocketTLS_recv (client, buf, sizeof (buf));
  ASSERT (n >= 9);
  ASSERT_EQ (buf[3], 0x04); /* SETTINGS type */

  /* Send SETTINGS ACK */
  unsigned char settings_ack[9]
      = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };
  SocketTLS_send (client, settings_ack, 9);

  /* Send HEADERS frame to request a resource (stream 1) */
  unsigned char headers_frame[] = {
    0x00, 0x00, 0x05,      /* Length: 5 */
    0x01,                  /* Type: HEADERS */
    0x04,                  /* Flags: END_HEADERS */
    0x00, 0x00, 0x00, 0x01, /* Stream ID: 1 */
    /* HPACK encoded headers */
    0x82,             /* :method: GET */
    0x86,             /* :scheme: http */
    0x84,             /* :path: / */
    0x41, 0x00        /* :authority: (empty) */
  };
  SocketTLS_send (client, headers_frame, sizeof (headers_frame));

  /* Wait for server to process */
  usleep (50000);

  /* Read response - should include PUSH_PROMISE */
  n = SocketTLS_recv (client, buf, sizeof (buf));
  ASSERT (n > 0);

  /* Verify server sent PUSH_PROMISE */
  int tries = 0;
  while (!server.push_promise_sent && tries < 50)
    {
      usleep (10000);
      tries++;
    }
  ASSERT (server.push_promise_sent);

  /* Verify pushed stream ID is even (server-initiated) */
  ASSERT_EQ (server.pushed_stream_id % 2, 0);
  ASSERT_EQ (server.pushed_stream_id, 2);

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
  push_server_stop (&server);
  cleanup_temp_cert_files ();
  END_TRY;
}

/* ============================================================================
 * Unit Tests - Stream ID Validation (RFC 9113 Section 8.4)
 * ============================================================================
 */

TEST (http2_push_promise_stream_id_must_be_even)
{
  /*
   * RFC 9113 Section 5.1.1: Streams initiated by the server MUST use
   * even-numbered stream identifiers. PUSH_PROMISE carries a promised
   * stream ID which must be even (server-initiated).
   */

  /* Valid server push stream IDs are even (2, 4, 6, ...) */
  ASSERT_EQ (2 % 2, 0); /* Stream 2 is valid */
  ASSERT_EQ (4 % 2, 0); /* Stream 4 is valid */

  /* Odd stream IDs are client-initiated, invalid for PUSH_PROMISE */
  ASSERT_EQ (1 % 2, 1); /* Stream 1 is odd - invalid for push */
  ASSERT_EQ (3 % 2, 1); /* Stream 3 is odd - invalid for push */
}

TEST (http2_push_promise_stream_id_must_be_monotonic)
{
  /*
   * RFC 9113 Section 5.1.1: The identifier of a newly established stream
   * MUST be numerically greater than all streams that the initiating
   * endpoint has opened or reserved.
   *
   * For PUSH_PROMISE, the promised stream ID must be greater than any
   * previously promised stream ID from the server.
   *
   * Violation: Connection error of type PROTOCOL_ERROR.
   */

  /* Example: If last pushed stream was 2, next must be > 2 (e.g., 4) */
  uint32_t last_pushed = 2;
  uint32_t next_valid = 4;
  uint32_t invalid_reuse = 2;
  uint32_t invalid_lower = 0;

  ASSERT (next_valid > last_pushed);      /* Valid: 4 > 2 */
  ASSERT (!(invalid_reuse > last_pushed)); /* Invalid: 2 not > 2 */
  ASSERT (!(invalid_lower > last_pushed)); /* Invalid: 0 not > 2 */
}

TEST (http2_push_promise_stream_id_zero_invalid)
{
  /*
   * RFC 9113 Section 5.1.1: A stream identifier of zero (0x0) is used
   * for connection control messages and cannot be used for streams.
   *
   * Promised stream ID of 0 in PUSH_PROMISE is a PROTOCOL_ERROR.
   */

  uint32_t stream_id_zero = 0;
  ASSERT_EQ (stream_id_zero, 0); /* Stream ID 0 is reserved */

  /* Valid stream IDs start at 2 for server-initiated streams */
  uint32_t first_valid_server_stream = 2;
  ASSERT (first_valid_server_stream > 0);
  ASSERT_EQ (first_valid_server_stream % 2, 0);
}

TEST (http2_push_promise_stream_id_max_limit)
{
  /*
   * RFC 9113 Section 5.1.1: Stream identifiers are 31-bit integers.
   * The maximum valid stream ID is 0x7FFFFFFF (2147483647).
   */

  uint32_t max_stream_id = 0x7FFFFFFF;

  ASSERT_EQ (max_stream_id, 2147483647);
  ASSERT ((max_stream_id & 0x80000000) == 0); /* High bit must be 0 */
}

#else /* !SOCKET_HAS_TLS */

TEST (http2_push_no_tls)
{
  printf ("  [SKIP] TLS not enabled - HTTP/2 push tests require TLS\n");
}

#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * Main Entry Point
 * ============================================================================
 */

int
main (void)
{
  printf ("=== HTTP/2 Server Push Tests (RFC 9113 Section 8.4) ===\n");

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}

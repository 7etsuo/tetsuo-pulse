/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 *
 * server_harness.c - HTTP/2 server harness for protocol fuzzing
 *
 * This is a standalone HTTP/2 server that can be targeted by external
 * protocol fuzzers like http2fuzz.
 *
 * Usage:
 *   ./http2_server_harness [port]
 *
 * Build:
 *   cmake -B build -DENABLE_TLS=ON -DBUILD_PROTOCOL_FUZZ_HARNESSES=ON
 *   cmake --build build --target http2_server_harness
 */

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

#define DEFAULT_PORT 8443
#define H2_CLIENT_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_CLIENT_PREFACE_LEN 24
#define MAX_FRAME_SIZE 16384

static volatile sig_atomic_t running = 1;

static void
signal_handler (int sig)
{
  (void)sig;
  running = 0;
}

/* Embedded test certificates */
static const char TEST_KEY[]
    = "-----BEGIN PRIVATE KEY-----\n"
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqkgE0iD0EUWZWzYQ\n"
      "XPgPfWGp4MGrE4FPN/MDwYGORquhRANCAASwKN6KryxfWQbBfknOxly7VFOrXn6Z\n"
      "Lx80K2pR/AIXpwibHHzr5vKf00UR6zNEscqQLhWJSJJcuG8hBbynYCvm\n"
      "-----END PRIVATE KEY-----\n";

static const char TEST_CERT[]
    = "-----BEGIN CERTIFICATE-----\n"
      "MIIBfDCCASOgAwIBAgIUKYoMAZV9MVBUq0Hi8Chy7C6UxBYwCgYIKoZIzj0EAwIw\n"
      "FDESMBAGA1UEAwwJZnV6ei10ZXN0MB4XDTI1MTEzMDEwMDIxNVoXDTM1MTEyODEw\n"
      "MDIxNVowFDESMBAGA1UEAwwJZnV6ei10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
      "AQcDQgAEsCjeiq8sX1kGwX5JzsZcu1RTq15+mS8fNCtqUfwCF6cImxx86+byn9NF\n"
      "EeszRLHKkC4ViUiSXLhvIQW8hBbynYCvm6NTMFEwHQYDVR0OBBYEFBk3lmJFZing\n"
      "lIKAu9KZQSeUqfcDMB8GA1UdIwQYMBaAFBk3lmJFZinglIKAu9KZQSeUqfcDMA8G\n"
      "A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgDkw1tp53edwA4IPoI8rU\n"
      "0wbkWAGfRnGNsGUViJrP8XMCIDuhYZqAaESAYlEcz5af64sL2gGRp4v8dcr9tr42\n"
      "L6vR\n"
      "-----END CERTIFICATE-----\n";

static char cert_file[64];
static char key_file[64];

static int
create_temp_certs (void)
{
  FILE *f;
  snprintf (cert_file, sizeof (cert_file), "/tmp/h2_cert_%d.pem", getpid ());
  snprintf (key_file, sizeof (key_file), "/tmp/h2_key_%d.pem", getpid ());

  f = fopen (cert_file, "w");
  if (!f)
    return -1;
  fputs (TEST_CERT, f);
  fclose (f);

  f = fopen (key_file, "w");
  if (!f)
    {
      unlink (cert_file);
      return -1;
    }
  fputs (TEST_KEY, f);
  fclose (f);
  return 0;
}

static void
cleanup_certs (void)
{
  unlink (cert_file);
  unlink (key_file);
}

static void
handle_connection (Socket_T client, SocketTLSContext_T tls_ctx)
{
  unsigned char buf[MAX_FRAME_SIZE + 9];
  ssize_t n;

  TRY
  {
    /* Enable TLS */
    SocketTLS_enable (client, tls_ctx);

    /* Handshake loop */
    TLSHandshakeState hs;
    int loops = 0;
    do
      {
        hs = SocketTLS_handshake (client);
        if (hs == TLS_HANDSHAKE_ERROR)
          {
            fprintf (stderr, "[h2] Handshake error\n");
            RETURN;
          }
        if (++loops > 1000)
          {
            fprintf (stderr, "[h2] Handshake timeout\n");
            RETURN;
          }
        usleep (1000);
      }
    while (hs == TLS_HANDSHAKE_WANT_READ || hs == TLS_HANDSHAKE_WANT_WRITE);

    if (hs != TLS_HANDSHAKE_COMPLETE)
      RETURN;

    fprintf (stderr, "[h2] TLS handshake complete\n");

    /* Read HTTP/2 client preface */
    n = SocketTLS_recv (client, buf, H2_CLIENT_PREFACE_LEN);
    if (n != H2_CLIENT_PREFACE_LEN
        || memcmp (buf, H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN) != 0)
      {
        fprintf (stderr, "[h2] Invalid preface (%zd bytes)\n", n);
        RETURN;
      }

    fprintf (stderr, "[h2] HTTP/2 preface received\n");

    /* Send server SETTINGS frame */
    unsigned char settings[9] = { 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    SocketTLS_send (client, settings, 9);

    /* Frame loop */
    while (running)
      {
        /* Read frame header (9 bytes) */
        n = SocketTLS_recv (client, buf, 9);
        if (n <= 0)
          break;
        if (n < 9)
          {
            fprintf (stderr, "[h2] Short header (%zd)\n", n);
            break;
          }

        /* Parse frame header */
        uint32_t length = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8)
                          | buf[2];
        uint8_t type = buf[3];
        uint8_t flags = buf[4];
        uint32_t stream_id = ((uint32_t)(buf[5] & 0x7f) << 24)
                             | ((uint32_t)buf[6] << 16)
                             | ((uint32_t)buf[7] << 8) | buf[8];

        fprintf (stderr, "[h2] Frame: type=%u flags=0x%02x stream=%u len=%u\n",
                 type, flags, stream_id, length);

        /* Read payload */
        if (length > 0)
          {
            if (length > MAX_FRAME_SIZE)
              {
                fprintf (stderr, "[h2] Frame too large\n");
                break;
              }
            n = SocketTLS_recv (client, buf + 9, length);
            if (n != (ssize_t)length)
              break;
          }

        /* Respond to frames */
        switch (type)
          {
          case 0x04: /* SETTINGS */
            if (!(flags & 0x01))
              { /* Not ACK */
                unsigned char ack[9] = { 0, 0, 0, 0x04, 0x01, 0, 0, 0, 0 };
                SocketTLS_send (client, ack, 9);
              }
            break;
          case 0x06: /* PING */
            if (!(flags & 0x01))
              {
                buf[4] = 0x01; /* Set ACK flag */
                SocketTLS_send (client, buf, 9 + length);
              }
            break;
          case 0x07: /* GOAWAY */
            fprintf (stderr, "[h2] GOAWAY received\n");
            goto done;
          case 0x01: /* HEADERS */
            if (stream_id > 0)
              {
                /* Send 200 OK response */
                unsigned char resp[10]
                    = { 0, 0, 1, 0x01, 0x05, 0, 0, 0, 0, 0x88 };
                resp[5] = (stream_id >> 24) & 0x7f;
                resp[6] = (stream_id >> 16) & 0xff;
                resp[7] = (stream_id >> 8) & 0xff;
                resp[8] = stream_id & 0xff;
                SocketTLS_send (client, resp, 10);
              }
            break;
          }
      }
  done:;
  }
  EXCEPT (SocketTLS_Failed)
  {
    fprintf (stderr, "[h2] TLS error\n");
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    fprintf (stderr, "[h2] Handshake failed\n");
  }
  END_TRY;
}

int
main (int argc, char *argv[])
{
  volatile int port = DEFAULT_PORT;
  volatile Socket_T listen_sock = NULL;
  volatile SocketTLSContext_T tls_ctx = NULL;

  if (argc > 1)
    port = atoi (argv[1]);

  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  if (create_temp_certs () != 0)
    {
      fprintf (stderr, "Failed to create certificates\n");
      return 1;
    }

  TRY
  {
    /* Create TLS context */
    tls_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    const char *alpn[] = { "h2" };
    SocketTLSContext_set_alpn_protos (tls_ctx, alpn, 1);
    SocketTLSContext_set_verify_mode (tls_ctx, TLS_VERIFY_NONE);

    /* Create listen socket */
    listen_sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (listen_sock);
    Socket_bind (listen_sock, "0.0.0.0", port);
    Socket_listen (listen_sock, 16);
    Socket_settimeout (listen_sock, 1);

    fprintf (stderr, "HTTP/2 harness on port %d\n", port);
    fprintf (stderr, "Run: http2fuzz -target=localhost:%d\n\n", port);

    while (running)
      {
        Socket_T client = Socket_accept (listen_sock);
        if (client)
          {
            fprintf (stderr, "[h2] Connection\n");
            handle_connection (client, tls_ctx);
            Socket_free (&client);
            fprintf (stderr, "[h2] Closed\n\n");
          }
      }
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "Socket error\n");
  }
  EXCEPT (SocketTLS_Failed)
  {
    fprintf (stderr, "TLS error\n");
  }
  END_TRY;

  /* Cleanup - cast away volatile for free functions */
  {
    Socket_T sock = (Socket_T)listen_sock;
    SocketTLSContext_T ctx = (SocketTLSContext_T)tls_ctx;
    if (sock)
      Socket_free (&sock);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  cleanup_certs ();

  return 0;
}

#else /* !SOCKET_HAS_TLS */
int
main (void)
{
  fprintf (stderr, "TLS support required\n");
  return 1;
}
#endif

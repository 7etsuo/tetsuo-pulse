/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 *
 * server_harness.c - TLS server harness for protocol fuzzing
 *
 * This is a standalone TLS echo server that can be targeted by tlsfuzzer
 * for protocol conformance testing.
 *
 * Usage:
 *   ./tls_server_harness [port] [--rsa]
 *
 * Build:
 *   cmake -B build -DENABLE_TLS=ON -DBUILD_PROTOCOL_FUZZ_HARNESSES=ON
 *   cmake --build build --target tls_server_harness
 */

#include <arpa/inet.h>
#include <getopt.h>
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

#define DEFAULT_PORT 4433
#define RECV_BUFFER_SIZE 16384

static volatile sig_atomic_t running = 1;

static void
signal_handler (int sig)
{
  (void)sig;
  running = 0;
}

/* EC certificate */
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
create_temp_certs (int use_rsa)
{
  FILE *f;

  snprintf (cert_file, sizeof (cert_file), "/tmp/tls_cert_%d.pem", getpid ());
  snprintf (key_file, sizeof (key_file), "/tmp/tls_key_%d.pem", getpid ());

  if (use_rsa)
    {
      char cmd[512];
      snprintf (cmd, sizeof (cmd),
                "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
                "-days 365 -nodes -subj '/CN=localhost' 2>/dev/null",
                key_file, cert_file);
      return system (cmd);
    }

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
  unsigned char buf[RECV_BUFFER_SIZE];
  ssize_t n;

  TRY
  {
    /* Enable TLS */
    SocketTLS_enable (client, tls_ctx);

    /* Handshake */
    TLSHandshakeState hs;
    int loops = 0;
    do
      {
        hs = SocketTLS_handshake (client);
        if (hs == TLS_HANDSHAKE_ERROR)
          {
            fprintf (stderr, "[tls] Handshake error\n");
            RETURN;
          }
        if (++loops > 1000)
          {
            fprintf (stderr, "[tls] Handshake timeout\n");
            RETURN;
          }
        usleep (1000);
      }
    while (hs == TLS_HANDSHAKE_WANT_READ || hs == TLS_HANDSHAKE_WANT_WRITE);

    if (hs != TLS_HANDSHAKE_COMPLETE)
      RETURN;

    const char *version = SocketTLS_get_version (client);
    const char *cipher = SocketTLS_get_cipher (client);
    fprintf (stderr, "[tls] Handshake: %s / %s\n", version ? version : "?",
             cipher ? cipher : "?");

    /* Echo loop */
    while (running)
      {
        n = SocketTLS_recv (client, buf, sizeof (buf));
        if (n <= 0)
          break;

        fprintf (stderr, "[tls] Recv %zd bytes, echo\n", n);
        SocketTLS_send (client, buf, n);
      }

    SocketTLS_shutdown (client);
  }
  EXCEPT (SocketTLS_Failed)
  {
    fprintf (stderr, "[tls] TLS error\n");
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    fprintf (stderr, "[tls] Handshake failed\n");
  }
  END_TRY;
}

int
main (int argc, char *argv[])
{
  volatile int port = DEFAULT_PORT;
  volatile int use_rsa = 0;
  volatile Socket_T listen_sock = NULL;
  volatile SocketTLSContext_T tls_ctx = NULL;

  static struct option opts[] = { { "rsa", no_argument, NULL, 'r' },
                                  { "help", no_argument, NULL, 'h' },
                                  { NULL, 0, NULL, 0 } };

  int opt;
  while ((opt = getopt_long (argc, argv, "rh", opts, NULL)) != -1)
    {
      switch (opt)
        {
        case 'r':
          use_rsa = 1;
          break;
        case 'h':
          fprintf (stderr, "Usage: %s [port] [--rsa]\n", argv[0]);
          return 0;
        }
    }

  if (optind < argc)
    port = atoi (argv[optind]);

  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  if (create_temp_certs (use_rsa) != 0)
    {
      fprintf (stderr, "Failed to create certificates\n");
      return 1;
    }

  TRY
  {
    tls_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    SocketTLSContext_set_verify_mode (tls_ctx, TLS_VERIFY_NONE);
    SocketTLSContext_enable_session_cache (tls_ctx, 1000, 7200);

    listen_sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (listen_sock);
    Socket_bind (listen_sock, "0.0.0.0", port);
    Socket_listen (listen_sock, 16);
    Socket_settimeout (listen_sock, 1);

    fprintf (stderr, "TLS harness on port %d (%s)\n", port,
             use_rsa ? "RSA" : "EC");
    fprintf (stderr,
             "Run: python3 -m tlsfuzzer.scripts.test-tls-version -h "
             "localhost -p %d\n\n",
             port);

    while (running)
      {
        Socket_T client = Socket_accept (listen_sock);
        if (client)
          {
            fprintf (stderr, "[tls] Connection\n");
            handle_connection (client, tls_ctx);
            Socket_free (&client);
            fprintf (stderr, "[tls] Closed\n\n");
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

#else
int
main (void)
{
  fprintf (stderr, "TLS support required\n");
  return 1;
}
#endif

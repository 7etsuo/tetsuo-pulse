/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * tls_client.c - TLS/SSL Client Example
 *
 * Demonstrates establishing a TLS connection using the SocketTLS API.
 * Shows certificate verification, cipher information, and secure
 * communication.
 *
 * Build:
 *   cmake -DENABLE_TLS=ON -DBUILD_EXAMPLES=ON ..
 *   make example_tls_client
 *
 * Usage:
 *   ./example_tls_client [host] [port]
 *   ./example_tls_client www.google.com 443
 *   ./example_tls_client github.com 443
 *
 * Note: Requires OpenSSL/LibreSSL support compiled in.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "core/SocketUtil.h"

#if SOCKET_HAS_TLS
#include "socket/Socket.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile host = "www.google.com";
  volatile int port = 443;
  Socket_T sock = NULL;
  SocketTLSContext_T tls_ctx = NULL;
  volatile int result = 0;

  /* Parse command line arguments */
  if (argc > 1)
    host = argv[1];
  if (argc > 2)
    port = atoi (argv[2]);

  if (port <= 0 || port > 65535)
    {
      fprintf (stderr, "Invalid port: %d\n", port);
      return 1;
    }

  /* Setup signal handling */
  signal (SIGPIPE, SIG_IGN);

  printf ("TLS Client Example\n");
  printf ("==================\n\n");
  printf ("Connecting to %s:%d over TLS\n\n", host, port);

  TRY
  {
    /* Create TCP socket */
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Connect to server */
    printf ("Establishing TCP connection...\n");
    Socket_connect (sock, host, port);

    printf ("TCP connection established\n");

    /* Create TLS context */
    printf ("Creating TLS context...\n");
    tls_ctx = SocketTLSContext_new_client (NULL);

    /* Enable TLS on socket */
    printf ("Enabling TLS...\n");
    SocketTLS_enable (sock, tls_ctx);

    /* Set server hostname for SNI and verification */
    SocketTLS_set_hostname (sock, host);

    /* Perform TLS handshake */
    printf ("Performing TLS handshake...\n");
    TLSHandshakeState state;
    while ((state = SocketTLS_handshake (sock)) == TLS_HANDSHAKE_WANT_READ
           || state == TLS_HANDSHAKE_WANT_WRITE)
      {
        /* Handshake in progress */
        printf (".");
        fflush (stdout);
        usleep (10000); /* 10ms */
      }

    if (state == TLS_HANDSHAKE_COMPLETE)
      {
        printf ("\n✅ TLS handshake successful!\n\n");

        /* Display connection information */
        printf ("TLS Version: %s\n", SocketTLS_get_version (sock));
        printf ("TLS Cipher:  %s\n", SocketTLS_get_cipher (sock));
        printf ("Server Name: %s\n", host);

        /* Check certificate verification */
        long verify_result = SocketTLS_get_verify_result (sock);
        if (verify_result == X509_V_OK)
          {
            printf ("Certificate: ✅ Verified\n");
          }
        else
          {
            printf ("Certificate: ❌ Verification failed (code: %ld)\n",
                    verify_result);
          }

        /* Check if session was reused */
        if (SocketTLS_is_session_reused (sock))
          {
            printf ("Session:     ✅ Reused\n");
          }
        else
          {
            printf ("Session:     New session\n");
          }

        /* Send HTTPS request */
        printf ("\nSending HTTPS request...\n");
        char request[512];
        snprintf (request, sizeof (request),
                  "GET / HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "Connection: close\r\n\r\n",
                  host);

        SocketTLS_send (sock, request, strlen (request));

        /* Read response */
        char buffer[4096];
        ssize_t n = SocketTLS_recv (sock, buffer, sizeof (buffer) - 1);

        if (n > 0)
          {
            buffer[n] = '\0';
            printf ("Received %zd bytes of response:\n", n);
            printf ("----------------------------------------\n");

            /* Print first few lines */
            char *line = strtok (buffer, "\n");
            int lines = 0;
            while (line && lines < 10)
              {
                printf ("%.80s%s\n", line, strlen (line) > 80 ? "..." : "");
                line = strtok (NULL, "\n");
                lines++;
              }

            if (strstr (buffer, "HTTP/1.1 200")
                || strstr (buffer, "HTTP/1.0 200"))
              {
                printf ("\n✅ HTTPS request successful!\n");
              }
            else
              {
                printf ("\n⚠️  Unexpected response\n");
              }
          }
        else
          {
            printf ("❌ No response received\n");
            result = 1;
          }

        /* Clean TLS shutdown */
        printf ("\nShutting down TLS connection...\n");
        SocketTLS_shutdown (sock);
      }
    else
      {
        printf ("\n❌ TLS handshake failed\n");
        result = 1;
      }
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "Socket error: %s\n", Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    fprintf (stderr, "TLS error: %s\n", Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    fprintf (stderr, "TLS handshake failed: %s\n", Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    fprintf (stderr, "TLS certificate verification failed: %s\n",
             Socket_GetLastError ());
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (tls_ctx)
    SocketTLSContext_free (&tls_ctx);
  if (sock)
    Socket_free (&sock);

  return result;
}

#else /* !SOCKET_HAS_TLS */

#include <stdio.h>

int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  fprintf (stderr, "TLS support not compiled in.\n");
  fprintf (stderr, "Rebuild with -DENABLE_TLS=ON\n");
  return 1;
}

#endif /* SOCKET_HAS_TLS */

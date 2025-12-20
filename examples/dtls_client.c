/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * dtls_client.c - DTLS (Datagram TLS) Client Example
 *
 * Demonstrates secure UDP communication using DTLS (RFC 6347).
 * Shows context creation, handshake, and encrypted datagram exchange.
 *
 * Build:
 *   cmake -DENABLE_TLS=ON -DBUILD_EXAMPLES=ON ..
 *   make example_dtls_client
 *
 * Usage:
 *   ./example_dtls_client [host] [port]
 *   ./example_dtls_client localhost 4433
 *
 * Test with OpenSSL server:
 *   openssl s_server -dtls -accept 4433 -cert server.pem -key server.key
 *
 * Note: Requires OpenSSL/LibreSSL with DTLS support compiled in.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketUtil.h"

#if SOCKET_HAS_TLS
#include "socket/SocketDgram.h"
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSContext.h"

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile host = "localhost";
  volatile int port = 4433;
  SocketDgram_T sock = NULL;
  SocketDTLSContext_T dtls_ctx = NULL;
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

  printf ("DTLS Client Example\n");
  printf ("===================\n\n");
  printf ("Connecting to %s:%d using DTLS\n\n", host, port);

  TRY
  {
    /* Create DTLS context for client */
    printf ("1. Creating DTLS client context...\n");
    dtls_ctx = SocketDTLSContext_new_client (NULL); /* NULL = system CA */

    /* Configure DTLS settings */
    printf ("   [OK] DTLS context created\n");
    printf ("   Setting minimum protocol to DTLS 1.2\n");
    SocketDTLSContext_set_min_protocol (dtls_ctx, DTLS1_2_VERSION);

    /* Set path MTU (typical for ethernet minus headers) */
    SocketDTLSContext_set_mtu (dtls_ctx, 1400);

    /* Create UDP socket */
    printf ("\n2. Creating UDP socket...\n");
    sock = SocketDgram_new (AF_INET);
    printf ("   [OK] UDP socket created\n");

    /* Connect UDP socket to establish default peer */
    printf ("   Connecting to %s:%d...\n", host, port);
    SocketDgram_connect (sock, host, port);
    printf ("   [OK] UDP socket connected\n");

    /* Enable DTLS on the socket */
    printf ("\n3. Enabling DTLS...\n");
    SocketDTLS_enable (sock, dtls_ctx);

    /* Set hostname for SNI and certificate verification */
    SocketDTLS_set_hostname (sock, host);
    printf ("   [OK] DTLS enabled with SNI: %s\n", host);

    /* Perform DTLS handshake with timeout */
    printf ("\n4. Performing DTLS handshake (timeout: 10s)...\n");
    DTLSHandshakeState state = SocketDTLS_handshake_loop (sock, 10000);

    if (state == DTLS_HANDSHAKE_COMPLETE)
      {
        printf ("   [OK] DTLS handshake successful!\n\n");

        /* Display connection information */
        printf ("5. Connection Information:\n");
        printf ("   DTLS Version: %s\n", SocketDTLS_get_version (sock));
        printf ("   Cipher Suite: %s\n", SocketDTLS_get_cipher (sock));

        /* Check if session was reused */
        if (SocketDTLS_is_session_reused (sock))
          {
            printf ("   Session: Reused (from cache)\n");
          }
        else
          {
            printf ("   Session: New handshake\n");
          }

        /* Check certificate verification */
        long verify_result = SocketDTLS_get_verify_result (sock);
        if (verify_result == 0)
          {
            printf ("   Certificate: [OK] Verified\n");
          }
        else
          {
            printf ("   Certificate: [WARN] Verification result: %ld\n",
                    verify_result);
          }

        /* Get effective MTU */
        size_t mtu = SocketDTLS_get_mtu (sock);
        printf ("   Effective MTU: %zu bytes\n", mtu);

        /* Send test message */
        printf ("\n6. Sending test message...\n");
        const char *message = "Hello from DTLS client!";
        ssize_t sent = SocketDTLS_send (sock, message, strlen (message));

        if (sent > 0)
          {
            printf ("   [OK] Sent %zd bytes: \"%s\"\n", sent, message);

            /* Wait for response with timeout */
            printf ("\n7. Waiting for response (timeout: 5s)...\n");
            SocketDgram_settimeout (sock, 5000);

            char buffer[1500];
            ssize_t received
                = SocketDTLS_recv (sock, buffer, sizeof (buffer) - 1);

            if (received > 0)
              {
                buffer[received] = '\0';
                printf ("   [OK] Received %zd bytes: \"%s\"\n", received,
                        buffer);
              }
            else if (received == 0)
              {
                printf ("   [INFO] No response received (peer closed)\n");
              }
            else
              {
                printf ("   [INFO] Timeout waiting for response\n");
              }
          }

        /* Graceful shutdown */
        printf ("\n8. Shutting down DTLS connection...\n");
        SocketDTLS_shutdown (sock);
        printf ("   [OK] DTLS shutdown complete\n");
      }
    else
      {
        printf ("   [FAIL] DTLS handshake failed (state: %d)\n", state);
        result = 1;
      }
  }
  EXCEPT (SocketDTLS_Failed)
  {
    fprintf (stderr, "\n[ERROR] DTLS error: %s\n", Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketDTLS_HandshakeFailed)
  {
    fprintf (stderr, "\n[ERROR] DTLS handshake failed: %s\n",
             Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketDTLS_VerifyFailed)
  {
    fprintf (stderr, "\n[ERROR] Certificate verification failed: %s\n",
             Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketDgram_Failed)
  {
    fprintf (stderr, "\n[ERROR] UDP socket error: %s\n",
             Socket_GetLastError ());
    result = 1;
  }
  ELSE
  {
    fprintf (stderr, "\n[ERROR] Unknown error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  printf ("\nCleaning up...\n");
  if (dtls_ctx)
    SocketDTLSContext_free (&dtls_ctx);
  if (sock)
    SocketDgram_free (&sock);

  printf ("\n%s\n", result == 0 ? "[OK] Example completed successfully!"
                                : "[FAIL] Example completed with errors");

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

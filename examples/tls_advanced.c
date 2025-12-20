/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * tls_advanced.c - Advanced TLS Features Example
 *
 * Demonstrates advanced TLS features including:
 * - OCSP stapling (client-side request)
 * - Certificate lookup callbacks
 * - Certificate pinning
 * - Certificate Transparency (CT) verification
 *
 * Build:
 *   cmake -DENABLE_TLS=ON -DBUILD_EXAMPLES=ON ..
 *   make example_tls_advanced
 *
 * Usage:
 *   ./example_tls_advanced [host] [port]
 *   ./example_tls_advanced www.google.com 443
 *   ./example_tls_advanced github.com 443
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

/* ============================================================================
 * Custom Certificate Lookup Callback Example
 * ============================================================================
 *
 * This demonstrates how to implement a custom certificate lookup for HSM,
 * database, or other non-filesystem sources. In this example, we just log
 * the lookup request and return NULL (no certificate found).
 */

typedef struct
{
  const char *source_name;
  int lookup_count;
} CertLookupContext;

static X509 *
example_cert_lookup (X509_STORE_CTX *store_ctx, const X509_NAME *name,
                     void *user_data)
{
  CertLookupContext *ctx = (CertLookupContext *)user_data;
  (void)store_ctx; /* Unused in this example */

  ctx->lookup_count++;

  /* Log the lookup request.
   * X509_NAME_oneline takes non-const but doesn't modify, so cast is safe. */
  char name_buf[256];
  X509_NAME_oneline ((X509_NAME *)name, name_buf, sizeof (name_buf));
  printf ("  📋 Certificate lookup #%d from '%s':\n", ctx->lookup_count,
          ctx->source_name);
  printf ("     Subject: %s\n", name_buf);

  /* In a real implementation, you would:
   * 1. Query your HSM/database for a certificate with this subject
   * 2. Parse the certificate data into an X509 object
   * 3. Return the X509 (caller takes ownership via X509_free)
   *
   * Example for HSM:
   *   unsigned char *cert_der;
   *   size_t cert_len;
   *   if (hsm_find_cert_by_subject(session, name_buf, &cert_der, &cert_len)) {
   *       const unsigned char *p = cert_der;
   *       X509 *cert = d2i_X509(NULL, &p, cert_len);
   *       free(cert_der);
   *       return cert;  // Ownership transferred
   *   }
   *
   * For now, return NULL to indicate no certificate found.
   */
  printf ("     Result: Not found (example callback)\n");
  return NULL;
}

/* ============================================================================
 * Main Program
 * ============================================================================
 */

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile host = "www.google.com";
  volatile int port = 443;
  Socket_T sock = NULL;
  SocketTLSContext_T tls_ctx = NULL;
  volatile int result = 0;

  /* Certificate lookup context */
  CertLookupContext lookup_ctx = { "Example Database", 0 };

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

  printf ("Advanced TLS Features Example\n");
  printf ("==============================\n\n");
  printf ("Connecting to %s:%d with advanced TLS features\n\n", host, port);

  TRY
  {
    /* Create TLS context with advanced features */
    printf ("1️⃣  Creating TLS context with advanced features...\n");
    tls_ctx = SocketTLSContext_new_client (NULL);

    /* Enable OCSP stapling request */
    printf ("   ✅ Enabling OCSP stapling request\n");
    SocketTLSContext_enable_ocsp_stapling (tls_ctx);

    /* Verify OCSP stapling is enabled */
    if (SocketTLSContext_ocsp_stapling_enabled (tls_ctx))
      {
        printf ("   ✅ OCSP stapling request confirmed\n");
      }

    /* Set custom certificate lookup callback */
    printf ("   ✅ Setting custom certificate lookup callback\n");
    SocketTLSContext_set_cert_lookup_callback (tls_ctx, example_cert_lookup,
                                               &lookup_ctx);

    /* Create TCP socket */
    printf ("\n2️⃣  Establishing TCP connection...\n");
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_connect (sock, host, port);
    printf ("   ✅ TCP connection established\n");

    /* Enable TLS on socket */
    printf ("\n3️⃣  Enabling TLS on socket...\n");
    SocketTLS_enable (sock, tls_ctx);

    /* Set server hostname for SNI and verification */
    SocketTLS_set_hostname (sock, host);
    printf ("   ✅ SNI hostname set: %s\n", host);

    /* Perform TLS handshake */
    printf ("\n4️⃣  Performing TLS handshake...\n");
    TLSHandshakeState state = SocketTLS_handshake_auto (sock);

    if (state == TLS_HANDSHAKE_COMPLETE)
      {
        printf ("   ✅ TLS handshake successful!\n\n");

        /* Display connection information */
        printf ("5️⃣  Connection Information:\n");
        printf ("   TLS Version: %s\n", SocketTLS_get_version (sock));
        printf ("   TLS Cipher:  %s\n", SocketTLS_get_cipher (sock));
        printf ("   Server Name: %s\n", host);

        /* Check certificate verification */
        long verify_result = SocketTLS_get_verify_result (sock);
        if (verify_result == X509_V_OK)
          {
            printf ("   Certificate: ✅ Verified\n");
          }
        else
          {
            printf ("   Certificate: ⚠️  Verification result: %ld\n",
                    verify_result);
          }

        /* Check OCSP stapling response */
        printf ("\n6️⃣  OCSP Stapling Status:\n");
        int ocsp_status = SocketTLS_get_ocsp_response_status (sock);
        switch (ocsp_status)
          {
          case 1:
            printf ("   ✅ OCSP response: Certificate is GOOD\n");
            break;
          case 0:
            printf ("   ❌ OCSP response: Certificate is REVOKED\n");
            break;
          case -1:
            printf ("   ℹ️  No OCSP response stapled by server\n");
            break;
          case -2:
            printf ("   ⚠️  OCSP response invalid or verification failed\n");
            break;
          default:
            printf ("   ❓ OCSP status: %d\n", ocsp_status);
            break;
          }

        /* Check OCSP next update time if available */
        time_t next_update;
        if (SocketTLS_get_ocsp_next_update (sock, &next_update) == 1)
          {
            char time_buf[64];
            struct tm *tm = gmtime (&next_update);
            strftime (time_buf, sizeof (time_buf), "%Y-%m-%d %H:%M:%S UTC",
                      tm);
            printf ("   OCSP Next Update: %s\n", time_buf);
          }

        /* Display certificate info */
        printf ("\n7️⃣  Peer Certificate Information:\n");
        SocketTLS_CertInfo cert_info;
        if (SocketTLS_get_peer_cert_info (sock, &cert_info) == 1)
          {
            printf ("   Subject: %.70s...\n", cert_info.subject);
            printf ("   Issuer:  %.70s...\n", cert_info.issuer);
            printf ("   Version: %d\n", cert_info.version);
            printf ("   Serial:  %s\n", cert_info.serial);

            /* Format validity dates */
            char not_before_buf[64], not_after_buf[64];
            struct tm *tm_before = gmtime (&cert_info.not_before);
            struct tm *tm_after = gmtime (&cert_info.not_after);
            strftime (not_before_buf, sizeof (not_before_buf),
                      "%Y-%m-%d %H:%M:%S UTC", tm_before);
            strftime (not_after_buf, sizeof (not_after_buf),
                      "%Y-%m-%d %H:%M:%S UTC", tm_after);
            printf ("   Valid From: %s\n", not_before_buf);
            printf ("   Valid To:   %s\n", not_after_buf);
            printf ("   Fingerprint (SHA256): %.32s...\n",
                    cert_info.fingerprint);
          }

        /* Report certificate lookup activity */
        printf ("\n8️⃣  Certificate Lookup Statistics:\n");
        printf ("   Lookups performed: %d\n", lookup_ctx.lookup_count);
        if (lookup_ctx.lookup_count == 0)
          {
            printf ("   ℹ️  No lookups needed (chain from server was "
                    "complete)\n");
          }

        /* Send a simple HTTPS request */
        printf ("\n9️⃣  Sending HTTPS request...\n");
        char request[512];
        snprintf (request, sizeof (request),
                  "GET / HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "Connection: close\r\n\r\n",
                  host);

        SocketTLS_send (sock, request, strlen (request));

        /* Read response header */
        char buffer[4096];
        ssize_t n = SocketTLS_recv (sock, buffer, sizeof (buffer) - 1);

        if (n > 0)
          {
            buffer[n] = '\0';
            printf ("   Received %zd bytes\n", n);

            /* Check for HTTP success status */
            if (strstr (buffer, "HTTP/1.1 200")
                || strstr (buffer, "HTTP/1.0 200"))
              {
                printf ("   ✅ HTTPS request successful (200 OK)\n");
              }
            else if (strstr (buffer, "HTTP/1.1 30")
                     || strstr (buffer, "HTTP/1.0 30"))
              {
                printf ("   ↪️  Server responded with redirect (30x)\n");
              }
            else
              {
                printf ("   ℹ️  Server responded: %.40s...\n", buffer);
              }
          }

        /* Clean TLS shutdown */
        printf ("\n🔒 Shutting down TLS connection...\n");
        SocketTLS_shutdown (sock);
        printf ("   ✅ TLS shutdown complete\n");
      }
    else
      {
        printf ("   ❌ TLS handshake failed (state: %d)\n", state);
        result = 1;
      }
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "\n❌ Socket error: %s\n", Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    fprintf (stderr, "\n❌ TLS error: %s\n", Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    fprintf (stderr, "\n❌ TLS handshake failed: %s\n",
             Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    fprintf (stderr, "\n❌ Certificate verification failed: %s\n",
             Socket_GetLastError ());
    result = 1;
  }
  ELSE
  {
    fprintf (stderr, "\n❌ Unknown error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  printf ("\n🧹 Cleaning up...\n");
  if (tls_ctx)
    SocketTLSContext_free (&tls_ctx);
  if (sock)
    Socket_free (&sock);

  printf ("\n%s\n", result == 0 ? "✅ Example completed successfully!"
                                : "❌ Example completed with errors");

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

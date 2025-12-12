/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * http2_client.c - HTTP/2 Client Example
 *
 * Demonstrates HTTP/2 with ALPN negotiation and protocol detection.
 * The SocketHTTPClient automatically negotiates HTTP/2 when available.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_http2_client
 *
 * Usage:
 *   ./example_http2_client [url]
 *   ./example_http2_client https://www.google.com
 *
 * Note: HTTP/2 requires TLS (HTTPS). HTTP/2 cleartext (h2c) is also
 * supported but rarely used in practice.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "http/SocketHTTPClient.h"

static const char *
http_version_string (SocketHTTP_Version version)
{
  switch (version)
    {
    case HTTP_VERSION_1_0:
      return "HTTP/1.0";
    case HTTP_VERSION_1_1:
      return "HTTP/1.1";
    case HTTP_VERSION_2:
      return "HTTP/2";
    default:
      return "Unknown";
    }
}

int
main (int argc, char **argv)
{
  const char *volatile url = "https://www.google.com";
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response = { 0 };
  SocketHTTPClient_Config config;
  volatile int result = 0;

  /* Handle SIGPIPE for network operations */
  signal (SIGPIPE, SIG_IGN);

  /* Use command-line URL if provided */
  if (argc > 1)
    {
      url = argv[1];
    }

  printf ("HTTP/2 Client Example\n");
  printf ("=====================\n\n");
  printf ("Fetching: %s\n\n", url);

  TRY
  {
    /* Configure client to prefer HTTP/2 */
    SocketHTTPClient_config_defaults (&config);

    /* Set max version to HTTP/2 (this is the default) */
    config.max_version = HTTP_VERSION_2;

    /* Enable connection pooling for HTTP/2 multiplexing benefits */
    config.enable_connection_pool = 1;
    config.max_connections_per_host = 1; /* HTTP/2 needs only 1 connection */

    /* Create client with HTTP/2 configuration */
    client = SocketHTTPClient_new (&config);

    /* Perform GET request */
    if (SocketHTTPClient_get (client, url, &response) < 0)
      {
        fprintf (stderr, "Request failed\n");
        result = 1;
      }
    else
      {
        /* Print protocol information */
        printf ("Negotiated Protocol: %s\n",
                http_version_string (response.version));
        printf ("Status: %d\n", response.status_code);
        printf ("Body Length: %zu bytes\n\n", response.body_len);

        if (response.version == HTTP_VERSION_2)
          {
            printf ("SUCCESS: HTTP/2 connection established!\n\n");
            printf ("HTTP/2 Features:\n");
            printf ("  - Multiplexed streams over single TCP connection\n");
            printf ("  - Header compression (HPACK)\n");
            printf ("  - Binary framing\n");
            printf ("  - Server push capability\n");
          }
        else
          {
            printf ("Note: Server responded with %s\n",
                    http_version_string (response.version));
            printf (
                "HTTP/2 may not be supported by this server or endpoint.\n");
          }

        /* Print first part of response body */
        if (response.body && response.body_len > 0)
          {
            size_t display_len
                = response.body_len > 500 ? 500 : response.body_len;
            printf ("\nResponse Preview (%zu bytes):\n", display_len);
            printf ("----------------------------------------\n");
            fwrite (response.body, 1, display_len, stdout);
            if (response.body_len > 500)
              {
                printf ("\n... [truncated]\n");
              }
            printf ("\n----------------------------------------\n");
          }
      }
  }
  EXCEPT (SocketHTTPClient_DNSFailed)
  {
    fprintf (stderr, "DNS resolution failed\n");
    result = 1;
  }
  EXCEPT (SocketHTTPClient_ConnectFailed)
  {
    fprintf (stderr, "Connection failed\n");
    result = 1;
  }
  EXCEPT (SocketHTTPClient_TLSFailed)
  {
    fprintf (stderr, "TLS/SSL error - HTTP/2 requires valid TLS\n");
    result = 1;
  }
  EXCEPT (SocketHTTPClient_Timeout)
  {
    fprintf (stderr, "Request timed out\n");
    result = 1;
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    fprintf (stderr, "HTTP client error\n");
    result = 1;
  }
  FINALLY
  {
    SocketHTTPClient_Response_free (&response);
    if (client)
      {
        SocketHTTPClient_free (&client);
      }
  }
  END_TRY;

  return result;
}

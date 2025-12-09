/**
 * http_get.c - Simple HTTP GET Request Example
 *
 * Demonstrates basic HTTP GET using the SocketHTTPClient API.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_http_get
 *
 * Usage:
 *   ./example_http_get [url]
 *   ./example_http_get https://example.com
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "http/SocketHTTPClient.h"

int
main (int argc, char **argv)
{
  const char *volatile url = "https://example.com";
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response = { 0 };
  volatile int result = 0;

  /* Handle SIGPIPE for network operations */
  signal (SIGPIPE, SIG_IGN);

  /* Use command-line URL if provided */
  if (argc > 1)
    {
      url = argv[1];
    }

  printf ("Fetching: %s\n\n", url);

  TRY
  {
    /* Create HTTP client with default configuration */
    client = SocketHTTPClient_new (NULL);

    /* Perform GET request */
    if (SocketHTTPClient_get (client, url, &response) < 0)
      {
        fprintf (stderr, "Request failed\n");
        result = 1;
      }
    else
      {
        /* Print response information */
        printf ("Status: %d\n", response.status_code);
        printf ("HTTP Version: %d.%d\n",
                response.version == HTTP_VERSION_2 ? 2 : 1,
                response.version == HTTP_VERSION_1_0 ? 0 : 1);
        printf ("Body Length: %zu bytes\n\n", response.body_len);

        /* Print response body (truncated for display) */
        if (response.body && response.body_len > 0)
          {
            size_t display_len
                = response.body_len > 1000 ? 1000 : response.body_len;
            printf ("Body (first %zu bytes):\n", display_len);
            printf ("----------------------------------------\n");
            fwrite (response.body, 1, display_len, stdout);
            if (response.body_len > 1000)
              {
                printf ("\n... [truncated]\n");
              }
            printf ("\n----------------------------------------\n");
          }
      }
  }
  EXCEPT (SocketHTTPClient_DNSFailed)
  {
    fprintf (stderr, "DNS resolution failed for URL: %s\n", url);
    result = 1;
  }
  EXCEPT (SocketHTTPClient_ConnectFailed)
  {
    fprintf (stderr, "Connection failed\n");
    result = 1;
  }
  EXCEPT (SocketHTTPClient_TLSFailed)
  {
    fprintf (stderr, "TLS/SSL error (certificate verification failed?)\n");
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
    /* Clean up response resources */
    SocketHTTPClient_Response_free (&response);

    /* Clean up client */
    if (client)
      {
        SocketHTTPClient_free (&client);
      }
  }
  END_TRY;

  return result;
}

/**
 * http_get.c - HTTP GET Request Examples
 *
 * Demonstrates various HTTP GET operations using SocketHTTPClient APIs:
 * - Basic GET request
 * - JSON GET with automatic parsing
 * - File download
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_http_get
 *
 * Usage:
 *   ./example_http_get [url]
 *   ./example_http_get https://httpbin.org/json
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

    /* Free first response */
    SocketHTTPClient_Response_free (&response);
    memset (&response, 0, sizeof (response));

    /* Method 2: JSON GET with automatic parsing */
    printf ("\n=== Using JSON GET API ===\n\n");

    const char *json_url = "https://httpbin.org/json";
    if (strcmp (url, "https://example.com") != 0)
      {
        json_url = url; /* Use provided URL if it's not the default */
      }

    char *json_data = NULL;
    size_t json_len = 0;
    int json_status = SocketHTTPClient_json_get (client, json_url, &json_data, &json_len);

    if (json_status < 0)
      {
        fprintf (stderr, "JSON GET request failed\n");
        result = 1;
      }
    else
      {
        printf ("JSON Status: %d\n", json_status);
        printf ("JSON Length: %zu bytes\n\n", json_len);

        if (json_data && json_len > 0)
          {
            size_t display_len = json_len > 1000 ? 1000 : json_len;
            printf ("Parsed JSON Response:\n");
            printf ("----------------------------------------\n");
            fwrite (json_data, 1, display_len, stdout);
            if (json_len > 1000)
              {
                printf ("\n... [truncated]\n");
              }
            printf ("\n----------------------------------------\n");
          }

        /* Free JSON data */
        free (json_data);
      }

    /* Method 3: File Download */
    printf ("\n=== Using Download API ===\n\n");

    const char *download_url = "https://httpbin.org/image/png";
    const char *output_file = "/tmp/socket_download.png";

    if (SocketHTTPClient_download (client, download_url, output_file) < 0)
      {
        fprintf (stderr, "Download failed\n");
        result = 1;
      }
    else
      {
        printf ("Download successful!\n");
        printf ("Downloaded: %s\n", download_url);
        printf ("Saved to: %s\n", output_file);
        printf ("Use 'file %s' to verify the downloaded file.\n", output_file);
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

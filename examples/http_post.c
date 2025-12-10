/**
 * http_post.c - HTTP POST Examples
 *
 * Demonstrates HTTP POST operations using SocketHTTPClient APIs:
 * - Simple POST with JSON payload
 * - Request builder API with custom headers
 * - JSON POST with automatic serialization
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_http_post
 *
 * Usage:
 *   ./example_http_post [url]
 *   ./example_http_post https://httpbin.org/post
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "http/SocketHTTPClient.h"

/* Example JSON payload */
static const char *json_payload = "{\n"
                                  "  \"name\": \"Socket Library\",\n"
                                  "  \"version\": \"1.0.0\",\n"
                                  "  \"features\": [\"HTTP/1.1\", \"HTTP/2\", "
                                  "\"WebSocket\", \"TLS 1.3\"]\n"
                                  "}";

int
main (int argc, char **argv)
{
  const char *volatile url = "https://httpbin.org/post";
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

  printf ("POST to: %s\n", url);
  printf ("Payload:\n%s\n\n", json_payload);

  TRY
  {
    /* Create HTTP client with default configuration */
    client = SocketHTTPClient_new (NULL);

    /* Method 1: Simple POST API */
    printf ("=== Using Simple POST API ===\n\n");

    if (SocketHTTPClient_post (client, url, "application/json", json_payload,
                               strlen (json_payload), &response)
        < 0)
      {
        fprintf (stderr, "Request failed\n");
        result = 1;
      }
    else
      {
        printf ("Status: %d\n", response.status_code);
        printf ("Body Length: %zu bytes\n\n", response.body_len);

        /* Print response body */
        if (response.body && response.body_len > 0)
          {
            size_t display_len
                = response.body_len > 2000 ? 2000 : response.body_len;
            printf ("Response:\n");
            fwrite (response.body, 1, display_len, stdout);
            printf ("\n");
          }
      }

    /* Free first response */
    SocketHTTPClient_Response_free (&response);
    memset (&response, 0, sizeof (response));

    /* Method 2: Request Builder API (more control) */
    printf ("\n=== Using Request Builder API ===\n\n");

    SocketHTTPClient_Request_T req
        = SocketHTTPClient_Request_new (client, HTTP_METHOD_POST, url);

    if (req)
      {
        /* Add custom headers */
        SocketHTTPClient_Request_header (req, "Content-Type",
                                         "application/json");
        SocketHTTPClient_Request_header (req, "X-Custom-Header",
                                         "socket-library-example");
        SocketHTTPClient_Request_header (req, "Accept", "application/json");

        /* Set request body */
        SocketHTTPClient_Request_body (req, json_payload,
                                       strlen (json_payload));

        /* Set timeout (10 seconds) */
        SocketHTTPClient_Request_timeout (req, 10000);

        /* Execute request */
        if (SocketHTTPClient_Request_execute (req, &response) < 0)
          {
            fprintf (stderr, "Request execution failed\n");
            result = 1;
          }
        else
          {
            printf ("Status: %d\n", response.status_code);
            printf ("Body Length: %zu bytes\n\n", response.body_len);

            if (response.body && response.body_len > 0)
              {
                size_t display_len
                    = response.body_len > 2000 ? 2000 : response.body_len;
                printf ("Response:\n");
                fwrite (response.body, 1, display_len, stdout);
                printf ("\n");
              }
          }

        /* Free request builder */
        SocketHTTPClient_Request_free (&req);
      }

    /* Free second response */
    SocketHTTPClient_Response_free (&response);
    memset (&response, 0, sizeof (response));

    /* Method 3: JSON POST with automatic serialization */
    printf ("\n=== Using JSON POST API ===\n\n");

    char *json_response = NULL;
    size_t json_response_len = 0;
    int json_post_status = SocketHTTPClient_json_post (client, url, json_payload,
                                                       &json_response, &json_response_len);

    if (json_post_status < 0)
      {
        fprintf (stderr, "JSON POST request failed\n");
        result = 1;
      }
    else
      {
        printf ("JSON POST Status: %d\n", json_post_status);
        printf ("Response Length: %zu bytes\n\n", json_response_len);

        if (json_response && json_response_len > 0)
          {
            size_t display_len = json_response_len > 2000 ? 2000 : json_response_len;
            printf ("JSON POST Response:\n");
            fwrite (json_response, 1, display_len, stdout);
            printf ("\n");
          }

        /* Free JSON response */
        free (json_response);
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
    fprintf (stderr, "TLS/SSL error\n");
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

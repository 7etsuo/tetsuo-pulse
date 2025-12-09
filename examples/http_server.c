/**
 * http_server.c - Basic HTTP Server Example
 *
 * Demonstrates a simple HTTP server using the SocketHTTPServer API.
 * Supports HTTP/1.1 with keep-alive.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_http_server
 *
 * Usage:
 *   ./example_http_server [port]
 *   ./example_http_server 8080
 *
 * Test with:
 *   curl http://localhost:8080/
 *   curl http://localhost:8080/hello
 *   curl http://localhost:8080/json
 *   curl -X POST -d "test=data" http://localhost:8080/echo
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTPServer.h"

/* Global flag for graceful shutdown */
static volatile int running = 1;

static void
signal_handler (int signo)
{
  (void)signo;
  running = 0;
}

/**
 * HTTP request handler
 *
 * Routes requests based on path and responds appropriately.
 */
static void
request_handler (SocketHTTPServer_Request_T req, void *userdata)
{
  (void)userdata;

  SocketHTTP_Method method = SocketHTTPServer_Request_method (req);
  const char *path = SocketHTTPServer_Request_path (req);
  const char *client = SocketHTTPServer_Request_client_addr (req);

  printf ("[%s] %s %s\n", client, SocketHTTP_method_name (method), path);

  /* Route based on path */
  if (strcmp (path, "/") == 0)
    {
      /* Home page */
      const char *html
          = "<!DOCTYPE html>\n"
            "<html>\n"
            "<head><title>Socket Library HTTP Server</title></head>\n"
            "<body>\n"
            "<h1>Welcome to Socket Library HTTP Server</h1>\n"
            "<p>This is a demonstration HTTP server.</p>\n"
            "<h2>Available Endpoints:</h2>\n"
            "<ul>\n"
            "  <li><a href=\"/\">/</a> - This page</li>\n"
            "  <li><a href=\"/hello\">/hello</a> - Hello World</li>\n"
            "  <li><a href=\"/json\">/json</a> - JSON response</li>\n"
            "  <li><code>POST /echo</code> - Echo request body</li>\n"
            "  <li><a href=\"/stats\">/stats</a> - Server statistics</li>\n"
            "</ul>\n"
            "</body>\n"
            "</html>\n";

      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type",
                                       "text/html; charset=utf-8");
      SocketHTTPServer_Request_body_string (req, html);
    }
  else if (strcmp (path, "/hello") == 0)
    {
      /* Simple text response */
      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
      SocketHTTPServer_Request_body_string (req, "Hello, World!\n");
    }
  else if (strcmp (path, "/json") == 0)
    {
      /* JSON response */
      const char *json = "{\n"
                         "  \"message\": \"Hello from Socket Library\",\n"
                         "  \"version\": \"1.0.0\",\n"
                         "  \"features\": [\n"
                         "    \"HTTP/1.1\",\n"
                         "    \"HTTP/2\",\n"
                         "    \"WebSocket\",\n"
                         "    \"TLS 1.3\"\n"
                         "  ]\n"
                         "}\n";

      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type",
                                       "application/json");
      SocketHTTPServer_Request_body_string (req, json);
    }
  else if (strcmp (path, "/echo") == 0 && method == HTTP_METHOD_POST)
    {
      /* Echo request body */
      const void *body = SocketHTTPServer_Request_body (req);
      size_t body_len = SocketHTTPServer_Request_body_len (req);

      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");

      if (body && body_len > 0)
        {
          SocketHTTPServer_Request_body_data (req, body, body_len);
        }
      else
        {
          SocketHTTPServer_Request_body_string (req, "(no body received)\n");
        }
    }
  else if (strcmp (path, "/stats") == 0)
    {
      /* This would normally get stats from userdata */
      const char *stats = "{\n"
                          "  \"status\": \"running\",\n"
                          "  \"uptime\": \"demo\"\n"
                          "}\n";

      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type",
                                       "application/json");
      SocketHTTPServer_Request_body_string (req, stats);
    }
  else
    {
      /* 404 Not Found */
      char body[256];
      snprintf (body, sizeof (body),
                "<!DOCTYPE html>\n"
                "<html>\n"
                "<head><title>404 Not Found</title></head>\n"
                "<body>\n"
                "<h1>404 Not Found</h1>\n"
                "<p>The requested URL %s was not found.</p>\n"
                "</body>\n"
                "</html>\n",
                path);

      SocketHTTPServer_Request_status (req, 404);
      SocketHTTPServer_Request_header (req, "Content-Type",
                                       "text/html; charset=utf-8");
      SocketHTTPServer_Request_body_string (req, body);
    }

  /* Always finish the response */
  SocketHTTPServer_Request_finish (req);
}

int
main (int argc, char **argv)
{
  volatile int port = 8080;
  SocketHTTPServer_T server = NULL;
  SocketHTTPServer_Config config;
  volatile int result = 0;

  /* Parse port from command line */
  if (argc > 1)
    {
      port = atoi (argv[1]);
      if (port <= 0 || port > 65535)
        {
          fprintf (stderr, "Invalid port: %s\n", argv[1]);
          return 1;
        }
    }

  /* Setup signal handlers for graceful shutdown */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  printf ("HTTP Server Example\n");
  printf ("===================\n\n");

  TRY
  {
    /* Configure server */
    SocketHTTPServer_config_defaults (&config);
    config.port = port;
    config.bind_address = "0.0.0.0"; /* Listen on all interfaces */
    config.backlog = 128;
    config.max_connections = 100;
    config.keepalive_timeout_ms = 60000;
    config.request_timeout_ms = 30000;
    config.max_header_size = 64 * 1024;
    config.max_body_size = 10 * 1024 * 1024;

    /* Create server */
    server = SocketHTTPServer_new (&config);

    /* Set request handler */
    SocketHTTPServer_set_handler (server, request_handler, NULL);

    /* Start listening */
    if (SocketHTTPServer_start (server) < 0)
      {
        fprintf (stderr, "Failed to start server\n");
        result = 1;
      }
    else
      {
        printf ("Server listening on http://0.0.0.0:%d\n", port);
        printf ("Press Ctrl+C to stop\n\n");

        /* Main event loop */
        while (running)
          {
            /* Process events with 1 second timeout */
            SocketHTTPServer_process (server, 1000);
          }

        printf ("\nShutting down...\n");
        SocketHTTPServer_stop (server);
      }
  }
  EXCEPT (SocketHTTPServer_BindFailed)
  {
    fprintf (stderr, "Failed to bind to port %d (in use?)\n", port);
    result = 1;
  }
  EXCEPT (SocketHTTPServer_Failed)
  {
    fprintf (stderr, "Server error\n");
    result = 1;
  }
  FINALLY
  {
    if (server)
      {
        SocketHTTPServer_free (&server);
      }
  }
  END_TRY;

  return result;
}

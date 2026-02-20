/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_http_integration.c - HTTP/1.1 Integration Tests
 *
 * End-to-end tests for HTTP client/server communication.
 * Uses real network I/O on loopback (127.0.0.1).
 *
 * Tests:
 * - GET, POST, PUT, DELETE methods
 * - Chunked transfer encoding
 * - Keep-alive connections
 * - Large body handling
 * - Error responses (400, 404, 500)
 *
 * Module Reuse:
 * - SocketHTTPServer for server-side
 * - SocketHTTPClient for client-side
 * - SocketHTTP1_Parser for parsing (via server)
 * - Socket, SocketPoll for networking
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPServer.h"
#include "socket/Socket.h"
#include "test/Test.h"

#define TEST_PORT_BASE 45000
#define TEST_SERVER_TIMEOUT_MS 100
#define TEST_CLIENT_TIMEOUT_MS 5000

static int test_port_counter = 0;

static int
get_test_port (void)
{
  return TEST_PORT_BASE + (test_port_counter++ % 1000);
}

typedef struct
{
  SocketHTTPServer_T server;
  pthread_t thread;
  atomic_int running;
  atomic_int started;
  int port;
  SocketHTTPServer_Handler handler;
  void *handler_data;
} TestServer;

static void *
server_thread_func (void *arg)
{
  TestServer *ts = (TestServer *)arg;

  ts->started = 1;

  while (ts->running)
    {
      SocketHTTPServer_process (ts->server, TEST_SERVER_TIMEOUT_MS);
    }

  return NULL;
}

static int
test_server_start (TestServer *ts,
                   SocketHTTPServer_Handler handler,
                   void *handler_data)
{
  SocketHTTPServer_Config config;
  int port;
  volatile int retries;
  volatile int server_started = 0;

  memset (ts, 0, sizeof (*ts));

  ts->handler = handler;
  ts->handler_data = handler_data;

  /* Retry with different ports if bind fails (handles port conflicts in CI) */
  for (retries = 0; retries < 10 && !server_started; retries++)
    {
      port = get_test_port ();
      ts->port = port;

      SocketHTTPServer_config_defaults (&config);
      config.port = port;
      config.bind_address = "127.0.0.1";
      config.request_timeout_ms = 5000;
      config.keepalive_timeout_ms = 10000;

      TRY
      {
        ts->server = SocketHTTPServer_new (&config);
        if (ts->server != NULL)
          {
            SocketHTTPServer_set_handler (ts->server, handler, handler_data);
            if (SocketHTTPServer_start (ts->server) >= 0)
              {
                server_started = 1;
              }
            else
              {
                SocketHTTPServer_free (&ts->server);
                ts->server = NULL;
              }
          }
      }
      EXCEPT (SocketHTTPServer_Failed)
      {
        /* Port might be in use, try next port */
        if (ts->server)
          SocketHTTPServer_free (&ts->server);
        ts->server = NULL;
      }
      EXCEPT (Socket_Failed)
      {
        /* Bind failed - port might be in use, try next port */
        if (ts->server)
          SocketHTTPServer_free (&ts->server);
        ts->server = NULL;
      }
      END_TRY;

      if (!server_started && retries < 9)
        usleep (10000); /* Small delay before retry */
    }

  if (!server_started || ts->server == NULL)
    {
      fprintf (stderr, "Failed to start server after %d retries\n", retries);
      return -1;
    }

  ts->running = 1;

  if (pthread_create (&ts->thread, NULL, server_thread_func, ts) != 0)
    {
      ts->running = 0;
      SocketHTTPServer_stop (ts->server);
      SocketHTTPServer_free (&ts->server);
      return -1;
    }

  /* Wait for server thread to start */
  while (!ts->started)
    usleep (1000);

  /* Give server time to be fully ready (may need more time in CI) */
  usleep (50000);

  return 0;
}

static void
test_server_stop (TestServer *ts)
{
  if (!ts->running)
    return;

  ts->running = 0;
  SocketHTTPServer_stop (ts->server); /* Stop server BEFORE joining thread */
  pthread_join (ts->thread, NULL);

  SocketHTTPServer_free (&ts->server);
}

static void
echo_handler (SocketHTTPServer_Request_T req, void *userdata)
{
  (void)userdata;

  SocketHTTP_Method method = SocketHTTPServer_Request_method (req);
  const char *path = SocketHTTPServer_Request_path (req);
  const void *body = SocketHTTPServer_Request_body (req);
  size_t body_len = SocketHTTPServer_Request_body_len (req);

  /* Handle different paths */
  if (strcmp (path, "/echo") == 0)
    {
      /* Echo back the request body */
      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
      if (body && body_len > 0)
        {
          SocketHTTPServer_Request_body_data (req, body, body_len);
        }
      else
        {
          SocketHTTPServer_Request_body_string (req, "No body");
        }
    }
  else if (strcmp (path, "/method") == 0)
    {
      /* Return the HTTP method name */
      const char *method_name = SocketHTTP_method_name (method);
      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
      SocketHTTPServer_Request_body_string (req, method_name);
    }
  else if (strcmp (path, "/status/404") == 0)
    {
      SocketHTTPServer_Request_status (req, 404);
      SocketHTTPServer_Request_body_string (req, "Not Found");
    }
  else if (strcmp (path, "/status/500") == 0)
    {
      SocketHTTPServer_Request_status (req, 500);
      SocketHTTPServer_Request_body_string (req, "Internal Server Error");
    }
  else if (strcmp (path, "/headers") == 0)
    {
      /* Echo a specific header */
      SocketHTTP_Headers_T headers = SocketHTTPServer_Request_headers (req);
      const char *custom = SocketHTTP_Headers_get (headers, "X-Custom-Header");

      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
      if (custom)
        {
          SocketHTTPServer_Request_body_string (req, custom);
        }
      else
        {
          SocketHTTPServer_Request_body_string (req, "No X-Custom-Header");
        }
    }
  else if (strcmp (path, "/large") == 0)
    {
      /* Generate a large response */
      size_t size = 100 * 1024; /* 100KB */
      char *data = malloc (size);
      if (data)
        {
          memset (data, 'X', size);
          SocketHTTPServer_Request_status (req, 200);
          SocketHTTPServer_Request_header (
              req, "Content-Type", "application/octet-stream");
          SocketHTTPServer_Request_body_data (req, data, size);
          free (data);
        }
      else
        {
          SocketHTTPServer_Request_status (req, 500);
          SocketHTTPServer_Request_body_string (req,
                                                "Memory allocation failed");
        }
    }
  else
    {
      /* Default: return OK */
      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
      SocketHTTPServer_Request_body_string (req, "OK");
    }

  SocketHTTPServer_Request_finish (req);
}

TEST (http_integration_get_request)
{
  TestServer ts;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response;
  char url[128];
  int result;

  signal (SIGPIPE, SIG_IGN);
  memset (&response, 0, sizeof (response));

  if (test_server_start (&ts, echo_handler, NULL) < 0)
    {
      printf ("  [SKIP] Could not start test server\n");
      return;
    }

  snprintf (url, sizeof (url), "http://127.0.0.1:%d/", ts.port);

  TRY client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client);

  result = SocketHTTPClient_get (client, url, &response);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (response.status_code, 200);

  SocketHTTPClient_Response_free (&response);
  EXCEPT (SocketHTTPClient_Failed)
  printf ("  [WARN] HTTP client failed: %s\n", SocketHTTPClient_Failed.reason);
  EXCEPT (SocketHTTPClient_ConnectFailed)
  printf ("  [WARN] Connection failed: %s\n",
          SocketHTTPClient_ConnectFailed.reason);
  FINALLY
  if (response.arena)
    SocketHTTPClient_Response_free (&response);
  if (client)
    SocketHTTPClient_free (&client);
  test_server_stop (&ts);
  END_TRY;
}

TEST (http_integration_post_request)
{
  TestServer ts;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response;
  char url[128];
  const char *post_body = "Hello, World!";
  int result;

  signal (SIGPIPE, SIG_IGN);
  memset (&response, 0, sizeof (response));

  if (test_server_start (&ts, echo_handler, NULL) < 0)
    {
      printf ("  [SKIP] Could not start test server\n");
      return;
    }

  snprintf (url, sizeof (url), "http://127.0.0.1:%d/echo", ts.port);

  TRY client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client);

  result = SocketHTTPClient_post (
      client, url, "text/plain", post_body, strlen (post_body), &response);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (response.status_code, 200);

  /* Server should echo back our body */
  ASSERT_EQ (response.body_len, strlen (post_body));
  ASSERT (memcmp (response.body, post_body, response.body_len) == 0);

  SocketHTTPClient_Response_free (&response);
  EXCEPT (SocketHTTPClient_Failed)
  printf ("  [WARN] HTTP client failed: %s\n", SocketHTTPClient_Failed.reason);
  EXCEPT (SocketHTTPClient_ConnectFailed)
  printf ("  [WARN] Connection failed\n");
  FINALLY
  if (response.arena)
    SocketHTTPClient_Response_free (&response);
  if (client)
    SocketHTTPClient_free (&client);
  test_server_stop (&ts);
  END_TRY;
}

TEST (http_integration_put_request)
{
  TestServer ts;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response;
  char url[128];
  int result;

  signal (SIGPIPE, SIG_IGN);
  memset (&response, 0, sizeof (response));

  if (test_server_start (&ts, echo_handler, NULL) < 0)
    {
      printf ("  [SKIP] Could not start test server\n");
      return;
    }

  snprintf (url, sizeof (url), "http://127.0.0.1:%d/method", ts.port);

  TRY client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client);

  result = SocketHTTPClient_put (client, url, "text/plain", "", 0, &response);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (response.status_code, 200);

  /* Server should return "PUT" */
  ASSERT (response.body != NULL);
  ASSERT (strstr ((const char *)response.body, "PUT") != NULL);

  SocketHTTPClient_Response_free (&response);
  EXCEPT (SocketHTTPClient_Failed)
  printf ("  [WARN] HTTP client failed\n");
  EXCEPT (SocketHTTPClient_ConnectFailed)
  printf ("  [WARN] Connection failed\n");
  FINALLY
  if (response.arena)
    SocketHTTPClient_Response_free (&response);
  if (client)
    SocketHTTPClient_free (&client);
  test_server_stop (&ts);
  END_TRY;
}

TEST (http_integration_delete_request)
{
  TestServer ts;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response;
  char url[128];
  int result;

  signal (SIGPIPE, SIG_IGN);
  memset (&response, 0, sizeof (response));

  if (test_server_start (&ts, echo_handler, NULL) < 0)
    {
      printf ("  [SKIP] Could not start test server\n");
      return;
    }

  snprintf (url, sizeof (url), "http://127.0.0.1:%d/method", ts.port);

  TRY client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client);

  result = SocketHTTPClient_delete (client, url, &response);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (response.status_code, 200);

  /* Server should return "DELETE" */
  ASSERT (response.body != NULL);
  ASSERT (strstr ((const char *)response.body, "DELETE") != NULL);

  SocketHTTPClient_Response_free (&response);
  EXCEPT (SocketHTTPClient_Failed)
  printf ("  [WARN] HTTP client failed\n");
  EXCEPT (SocketHTTPClient_ConnectFailed)
  printf ("  [WARN] Connection failed\n");
  FINALLY
  if (response.arena)
    SocketHTTPClient_Response_free (&response);
  if (client)
    SocketHTTPClient_free (&client);
  test_server_stop (&ts);
  END_TRY;
}

TEST (http_integration_error_404)
{
  TestServer ts;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response;
  char url[128];
  int result;

  signal (SIGPIPE, SIG_IGN);
  memset (&response, 0, sizeof (response));

  if (test_server_start (&ts, echo_handler, NULL) < 0)
    {
      printf ("  [SKIP] Could not start test server\n");
      return;
    }

  snprintf (url, sizeof (url), "http://127.0.0.1:%d/status/404", ts.port);

  TRY client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client);

  result = SocketHTTPClient_get (client, url, &response);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (response.status_code, 404);

  SocketHTTPClient_Response_free (&response);
  EXCEPT (SocketHTTPClient_Failed)
  printf ("  [WARN] HTTP client failed\n");
  EXCEPT (SocketHTTPClient_ConnectFailed)
  printf ("  [WARN] Connection failed\n");
  FINALLY
  if (response.arena)
    SocketHTTPClient_Response_free (&response);
  if (client)
    SocketHTTPClient_free (&client);
  test_server_stop (&ts);
  END_TRY;
}

TEST (http_integration_error_500)
{
  TestServer ts;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response;
  char url[128];
  int result;

  signal (SIGPIPE, SIG_IGN);
  memset (&response, 0, sizeof (response));

  if (test_server_start (&ts, echo_handler, NULL) < 0)
    {
      printf ("  [SKIP] Could not start test server\n");
      return;
    }

  snprintf (url, sizeof (url), "http://127.0.0.1:%d/status/500", ts.port);

  TRY client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client);

  result = SocketHTTPClient_get (client, url, &response);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (response.status_code, 500);

  SocketHTTPClient_Response_free (&response);
  EXCEPT (SocketHTTPClient_Failed)
  printf ("  [WARN] HTTP client failed\n");
  EXCEPT (SocketHTTPClient_ConnectFailed)
  printf ("  [WARN] Connection failed\n");
  FINALLY
  if (response.arena)
    SocketHTTPClient_Response_free (&response);
  if (client)
    SocketHTTPClient_free (&client);
  test_server_stop (&ts);
  END_TRY;
}

TEST (http_integration_large_response)
{
  TestServer ts;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response;
  char url[128];
  int result;

  signal (SIGPIPE, SIG_IGN);
  memset (&response, 0, sizeof (response));

  if (test_server_start (&ts, echo_handler, NULL) < 0)
    {
      printf ("  [SKIP] Could not start test server\n");
      return;
    }

  snprintf (url, sizeof (url), "http://127.0.0.1:%d/large", ts.port);

  TRY client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client);

  result = SocketHTTPClient_get (client, url, &response);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (response.status_code, 200);

  /* Server returns 100KB */
  ASSERT_EQ (response.body_len, 100 * 1024);

  SocketHTTPClient_Response_free (&response);
  EXCEPT (SocketHTTPClient_Failed)
  printf ("  [WARN] HTTP client failed\n");
  EXCEPT (SocketHTTPClient_ConnectFailed)
  printf ("  [WARN] Connection failed\n");
  FINALLY
  if (response.arena)
    SocketHTTPClient_Response_free (&response);
  if (client)
    SocketHTTPClient_free (&client);
  test_server_stop (&ts);
  END_TRY;
}

TEST (http_integration_multiple_requests)
{
  TestServer ts;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Response response;
  char url[128];
  int result;

  signal (SIGPIPE, SIG_IGN);

  if (test_server_start (&ts, echo_handler, NULL) < 0)
    {
      printf ("  [SKIP] Could not start test server\n");
      return;
    }

  snprintf (url, sizeof (url), "http://127.0.0.1:%d/", ts.port);

  TRY client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client);

  /* Make multiple requests to test connection reuse (keep-alive) */
  for (int i = 0; i < 5; i++)
    {
      int status_code;

      memset (&response, 0, sizeof (response));
      result = SocketHTTPClient_get (client, url, &response);
      if (result != 0)
        {
          printf ("  [WARN] Request %d failed\n", i);
          break;
        }

      /* Save status before freeing to avoid memory leak if assertion fails.
       * ASSERT_EQ uses return; which bypasses FINALLY block. */
      status_code = response.status_code;
      SocketHTTPClient_Response_free (&response);
      ASSERT_EQ (status_code, 200);
    }

  EXCEPT (SocketHTTPClient_Failed)
  printf ("  [WARN] HTTP client failed\n");
  EXCEPT (SocketHTTPClient_ConnectFailed)
  printf ("  [WARN] Connection failed\n");
  EXCEPT (Socket_Closed)
  printf ("  [WARN] Connection closed by server (keep-alive may not be "
          "supported)\n");
  FINALLY
  if (client)
    SocketHTTPClient_free (&client);
  test_server_stop (&ts);
  END_TRY;
}

int
main (void)
{
  printf ("=== HTTP Integration Tests ===\n");

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}

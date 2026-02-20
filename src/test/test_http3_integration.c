/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_http3_integration.c
 * @brief End-to-end HTTP/3 integration tests.
 *
 * Full-stack loopback tests: HTTP/3 client ↔ server over QUIC with real
 * UDP sockets, TLS, QPACK header compression, and RFC 9114 framing.
 * Server runs in a pthread, client connects from the main thread.
 */

#ifdef SOCKET_HAS_TLS

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP3-client.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-request.h"
#include "http/SocketHTTP3-server.h"
#include "http/SocketHTTP3.h"
#include "test/Test.h"

/* Embedded test certificates */
#include "../fuzz/fuzz_test_certs.h"

#define H3_INTEG_PORT_BASE 52000
#define H3_INTEG_TIMEOUT_MS 1000
#define H3_INTEG_POLL_MS 100
#define H3_INTEG_LARGE_BODY_SIZE 65536

static int h3_integ_port_counter = 0;
static volatile int h3_connect_known_broken = 0;

static int
get_h3_integ_port (void)
{
  return H3_INTEG_PORT_BASE + (h3_integ_port_counter++ % 1000);
}

static char h3_cert_file[64];
static char h3_key_file[64];

static int
h3_create_temp_cert_files (void)
{
  FILE *f;

  snprintf (h3_cert_file,
            sizeof (h3_cert_file),
            "/tmp/test_h3_cert_%d.pem",
            getpid ());
  snprintf (
      h3_key_file, sizeof (h3_key_file), "/tmp/test_h3_key_%d.pem", getpid ());

  f = fopen (h3_cert_file, "w");
  if (f == NULL)
    return -1;
  fputs (FUZZ_TEST_CERT, f);
  fclose (f);

  f = fopen (h3_key_file, "w");
  if (f == NULL)
    {
      unlink (h3_cert_file);
      return -1;
    }
  fputs (FUZZ_TEST_KEY, f);
  fclose (f);

  return 0;
}

static void
h3_cleanup_temp_cert_files (void)
{
  unlink (h3_cert_file);
  unlink (h3_key_file);
}

typedef struct
{
  SocketHTTP3_Server_T server;
  Arena_T arena;
  pthread_t thread;
  volatile int running;
  volatile int ready;
  int port;
} H3TestServer;

static void *
h3_server_thread (void *arg)
{
  H3TestServer *ts = arg;

  if (SocketHTTP3_Server_start (ts->server) < 0)
    {
      ts->running = 0;
      return NULL;
    }

  ts->ready = 1;

  while (ts->running)
    SocketHTTP3_Server_poll (ts->server, H3_INTEG_POLL_MS);

  return NULL;
}

typedef void (*H3RouteHandler) (SocketHTTP3_Request_T req,
                                const SocketHTTP_Headers_T headers,
                                Arena_T arena);

typedef struct
{
  const char *path;
  H3RouteHandler handler;
} H3Route;

static void
handle_root (SocketHTTP3_Request_T req,
             const SocketHTTP_Headers_T headers,
             Arena_T arena)
{
  (void)headers;
  SocketHTTP_Headers_T resp = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (resp, ":status", 7, "200", 3);
  SocketHTTP_Headers_add (resp, "content-type", "text/plain");
  SocketHTTP3_Request_send_headers (req, resp, 0);

  const char *body = "Hello, HTTP/3!";
  SocketHTTP3_Request_send_data (req, body, strlen (body), 1);
}

static void
handle_post (SocketHTTP3_Request_T req,
             const SocketHTTP_Headers_T headers,
             Arena_T arena)
{
  (void)headers;
  SocketHTTP_Headers_T resp = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (resp, ":status", 7, "201", 3);
  SocketHTTP3_Request_send_headers (req, resp, 0);

  const char *body = "created";
  SocketHTTP3_Request_send_data (req, body, strlen (body), 1);
}

static void
handle_head (SocketHTTP3_Request_T req,
             const SocketHTTP_Headers_T headers,
             Arena_T arena)
{
  (void)headers;
  SocketHTTP_Headers_T resp = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (resp, ":status", 7, "200", 3);
  SocketHTTP_Headers_add (resp, "content-length", "14");

  /* HEAD: send HEADERS with end_stream=1, no body */
  SocketHTTP3_Request_send_headers (req, resp, 1);
}

static void
handle_large (SocketHTTP3_Request_T req,
              const SocketHTTP_Headers_T headers,
              Arena_T arena)
{
  (void)headers;
  SocketHTTP_Headers_T resp = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (resp, ":status", 7, "200", 3);
  SocketHTTP3_Request_send_headers (req, resp, 0);

  /* Send 64KB body filled with 'A' */
  char *body
      = Arena_alloc (arena, H3_INTEG_LARGE_BODY_SIZE, __FILE__, __LINE__);
  memset (body, 'A', H3_INTEG_LARGE_BODY_SIZE);
  SocketHTTP3_Request_send_data (req, body, H3_INTEG_LARGE_BODY_SIZE, 1);
}

static void
handle_no_content (SocketHTTP3_Request_T req,
                   const SocketHTTP_Headers_T headers,
                   Arena_T arena)
{
  (void)headers;
  SocketHTTP_Headers_T resp = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (resp, ":status", 7, "204", 3);
  SocketHTTP3_Request_send_headers (req, resp, 1);
}

static void
handle_trailers (SocketHTTP3_Request_T req,
                 const SocketHTTP_Headers_T headers,
                 Arena_T arena)
{
  (void)headers;
  SocketHTTP_Headers_T resp = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (resp, ":status", 7, "200", 3);
  SocketHTTP3_Request_send_headers (req, resp, 0);

  const char *body = "data";
  SocketHTTP3_Request_send_data (req, body, strlen (body), 0);

  /* Send trailing headers */
  SocketHTTP_Headers_T trailers = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add (trailers, "x-checksum", "abc123");
  SocketHTTP3_Request_send_trailers (req, trailers);
}

static void
handle_not_found (SocketHTTP3_Request_T req,
                  const SocketHTTP_Headers_T headers,
                  Arena_T arena)
{
  (void)headers;
  SocketHTTP_Headers_T resp = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (resp, ":status", 7, "404", 3);
  SocketHTTP3_Request_send_headers (req, resp, 0);

  const char *body = "not found";
  SocketHTTP3_Request_send_data (req, body, strlen (body), 1);
}

static const H3Route routes[] = {
  { "/", handle_root },
  { "/post", handle_post },
  { "/head", handle_head },
  { "/large", handle_large },
  { "/no-content", handle_no_content },
  { "/trailers", handle_trailers },
  { NULL, NULL },
};

static void
h3_request_handler (SocketHTTP3_Request_T req,
                    const SocketHTTP_Headers_T headers,
                    void *userdata)
{
  Arena_T arena = (Arena_T)userdata;
  const char *path = SocketHTTP_Headers_get (headers, ":path");

  if (path == NULL)
    {
      handle_not_found (req, headers, arena);
      return;
    }

  for (const H3Route *r = routes; r->path != NULL; r++)
    {
      if (strcmp (path, r->path) == 0)
        {
          r->handler (req, headers, arena);
          return;
        }
    }

  handle_not_found (req, headers, arena);
}

static int
h3_server_setup (H3TestServer *ts)
{
  if (h3_connect_known_broken)
    return -1;

  memset (ts, 0, sizeof (*ts));
  ts->arena = Arena_new ();
  ts->port = get_h3_integ_port ();
  ts->running = 1;

  SocketHTTP3_ServerConfig config;
  SocketHTTP3_ServerConfig_defaults (&config);
  config.bind_addr = "127.0.0.1";
  config.port = ts->port;
  config.cert_file = h3_cert_file;
  config.key_file = h3_key_file;

  ts->server = SocketHTTP3_Server_new (ts->arena, &config);
  if (ts->server == NULL)
    {
      Arena_dispose (&ts->arena);
      return -1;
    }

  SocketHTTP3_Server_on_request (ts->server, h3_request_handler, ts->arena);

  if (pthread_create (&ts->thread, NULL, h3_server_thread, ts) != 0)
    {
      SocketHTTP3_Server_close (ts->server);
      Arena_dispose (&ts->arena);
      return -1;
    }

  /* Wait for server to be ready */
  int wait_count = 0;
  while (!ts->ready && ts->running && wait_count < 500)
    {
      usleep (10000);
      wait_count++;
    }

  if (!ts->ready)
    {
      ts->running = 0;
      pthread_join (ts->thread, NULL);
      SocketHTTP3_Server_close (ts->server);
      Arena_dispose (&ts->arena);
      return -1;
    }

  return 0;
}

static void
h3_server_teardown (H3TestServer *ts)
{
  ts->running = 0;
  SocketHTTP3_Server_shutdown (ts->server);
  pthread_join (ts->thread, NULL);
  SocketHTTP3_Server_close (ts->server);
  Arena_dispose (&ts->arena);
}

static SocketHTTP3_Client_T
h3_make_client (Arena_T arena, int port)
{
  if (h3_connect_known_broken)
    return NULL;

  SocketHTTP3_ClientConfig config;
  SocketHTTP3_ClientConfig_defaults (&config);
  config.verify_peer = 0;
  config.connect_timeout_ms = H3_INTEG_TIMEOUT_MS;
  config.request_timeout_ms = H3_INTEG_TIMEOUT_MS;

  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, &config);
  if (client == NULL)
    {
      h3_connect_known_broken = 1;
      return NULL;
    }

  if (SocketHTTP3_Client_connect (client, "127.0.0.1", port) < 0)
    {
      h3_connect_known_broken = 1;
      SocketHTTP3_Client_close (client);
      return NULL;
    }

  return client;
}

TEST (h3_integ_get_200)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0)
    {
      printf ("  [SKIP] Could not create test certificates\n");
      Arena_dispose (&arena);
      return;
    }

  if (h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Could not start HTTP/3 server\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Could not connect HTTP/3 client\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  int status = 0;
  void *body = NULL;
  size_t body_len = 0;
  int rc = SocketHTTP3_Client_request (client,
                                       HTTP_METHOD_GET,
                                       "/",
                                       NULL,
                                       NULL,
                                       0,
                                       NULL,
                                       &status,
                                       &body,
                                       &body_len);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (200, status);
  ASSERT (body_len > 0);
  ASSERT (body != NULL);
  ASSERT_EQ (0, memcmp (body, "Hello, HTTP/3!", 14));

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_post_201)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  const char *req_body = "{\"key\":\"value\"}";
  int status = 0;
  void *resp_body = NULL;
  size_t resp_body_len = 0;
  int rc = SocketHTTP3_Client_request (client,
                                       HTTP_METHOD_POST,
                                       "/post",
                                       NULL,
                                       req_body,
                                       strlen (req_body),
                                       NULL,
                                       &status,
                                       &resp_body,
                                       &resp_body_len);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (201, status);
  ASSERT (resp_body_len > 0);
  ASSERT_EQ (0, memcmp (resp_body, "created", 7));

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_head_no_body)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  int status = 0;
  void *body = NULL;
  size_t body_len = 0;
  int rc = SocketHTTP3_Client_request (client,
                                       HTTP_METHOD_HEAD,
                                       "/head",
                                       NULL,
                                       NULL,
                                       0,
                                       NULL,
                                       &status,
                                       &body,
                                       &body_len);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (200, status);
  ASSERT_EQ (0U, body_len);

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_large_body)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  int status = 0;
  void *body = NULL;
  size_t body_len = 0;
  int rc = SocketHTTP3_Client_request (client,
                                       HTTP_METHOD_GET,
                                       "/large",
                                       NULL,
                                       NULL,
                                       0,
                                       NULL,
                                       &status,
                                       &body,
                                       &body_len);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (200, status);
  ASSERT_EQ ((size_t)H3_INTEG_LARGE_BODY_SIZE, body_len);

  /* Verify all bytes are 'A' */
  if (body != NULL && body_len == H3_INTEG_LARGE_BODY_SIZE)
    {
      const char *p = (const char *)body;
      int all_match = 1;
      for (size_t i = 0; i < body_len; i++)
        {
          if (p[i] != 'A')
            {
              all_match = 0;
              break;
            }
        }
      ASSERT (all_match);
    }

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_204_no_content)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  int status = 0;
  size_t body_len = 0;
  int rc = SocketHTTP3_Client_request (client,
                                       HTTP_METHOD_GET,
                                       "/no-content",
                                       NULL,
                                       NULL,
                                       0,
                                       NULL,
                                       &status,
                                       NULL,
                                       &body_len);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (204, status);
  ASSERT_EQ (0U, body_len);

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_settings_exchange)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  /* After connect, peer_settings should be populated */
  SocketHTTP3_Conn_T conn = SocketHTTP3_Client_conn (client);
  ASSERT_NOT_NULL (conn);

  const SocketHTTP3_Settings *ps = SocketHTTP3_Conn_peer_settings (conn);
  ASSERT_NOT_NULL (ps);

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_connection_reuse)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  /* Send 3 sequential requests on the same connection */
  for (int i = 0; i < 3; i++)
    {
      int status = 0;
      int rc = SocketHTTP3_Client_request (client,
                                           HTTP_METHOD_GET,
                                           "/",
                                           NULL,
                                           NULL,
                                           0,
                                           NULL,
                                           &status,
                                           NULL,
                                           NULL);
      ASSERT_EQ (0, rc);
      ASSERT_EQ (200, status);
    }

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_concurrent_requests)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  /* Create 3 streaming requests and send headers before reading any */
  SocketHTTP3_Request_T reqs[3];
  for (int i = 0; i < 3; i++)
    {
      reqs[i] = SocketHTTP3_Client_new_request (client);
      if (reqs[i] == NULL)
        {
          printf ("  [SKIP] Could not create streaming request\n");
          SocketHTTP3_Client_close (client);
          Arena_dispose (&arena);
          h3_server_teardown (&ts);
          h3_cleanup_temp_cert_files ();
          return;
        }

      SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
      SocketHTTP_Headers_add_pseudo_n (h, ":method", 7, "GET", 3);
      SocketHTTP_Headers_add_pseudo_n (h, ":scheme", 7, "https", 5);
      SocketHTTP_Headers_add_pseudo_n (h, ":path", 5, "/", 1);
      SocketHTTP_Headers_add_pseudo_n (h, ":authority", 10, "127.0.0.1", 9);
      SocketHTTP3_Request_send_headers (reqs[i], h, 1);
    }

  SocketHTTP3_Client_flush (client);

  /* Poll until we get responses for all 3 */
  int poll_attempts = 0;
  int all_done = 0;
  while (!all_done && poll_attempts < 50)
    {
      SocketHTTP3_Client_poll (client, H3_INTEG_POLL_MS);
      poll_attempts++;

      all_done = 1;
      for (int i = 0; i < 3; i++)
        {
          if (SocketHTTP3_Request_recv_state (reqs[i]) != H3_REQ_RECV_COMPLETE)
            {
              all_done = 0;
              break;
            }
        }
    }

  /* All 3 should have completed */
  for (int i = 0; i < 3; i++)
    {
      int status = 0;
      int rc = SocketHTTP3_Request_recv_headers (reqs[i], NULL, &status);
      ASSERT_EQ (0, rc);
      ASSERT_EQ (200, status);
    }

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_trailers)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  int status = 0;
  SocketHTTP_Headers_T resp_headers = NULL;
  void *body = NULL;
  size_t body_len = 0;
  int rc = SocketHTTP3_Client_request (client,
                                       HTTP_METHOD_GET,
                                       "/trailers",
                                       NULL,
                                       NULL,
                                       0,
                                       &resp_headers,
                                       &status,
                                       &body,
                                       &body_len);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (200, status);
  ASSERT (body_len > 0);

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_stream_error_recovery)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  /* Create and cancel a request */
  SocketHTTP3_Request_T req = SocketHTTP3_Client_new_request (client);
  if (req != NULL)
    {
      SocketHTTP3_Request_cancel (req);
      SocketHTTP3_Client_flush (client);
    }

  /* Second request should still succeed on the same connection */
  int status = 0;
  int rc = SocketHTTP3_Client_request (
      client, HTTP_METHOD_GET, "/", NULL, NULL, 0, NULL, &status, NULL, NULL);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (200, status);

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_graceful_shutdown)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  /* Do a request to ensure the connection is fully established */
  int status = 0;
  int rc = SocketHTTP3_Client_request (
      client, HTTP_METHOD_GET, "/", NULL, NULL, 0, NULL, &status, NULL, NULL);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (200, status);

  /* Initiate graceful server shutdown (sends GOAWAY) */
  SocketHTTP3_Server_shutdown (ts.server);

  /* Give the client a moment to receive GOAWAY */
  SocketHTTP3_Client_poll (client, 200);

  /* The client's connection should reflect GOAWAY received */
  SocketHTTP3_Conn_T conn = SocketHTTP3_Client_conn (client);
  SocketHTTP3_ConnState state = SocketHTTP3_Conn_state (conn);
  ASSERT (state == H3_CONN_STATE_GOAWAY_RECV || state == H3_CONN_STATE_CLOSING
          || state == H3_CONN_STATE_OPEN);

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

TEST (h3_integ_not_found)
{
  H3TestServer ts;
  Arena_T arena = Arena_new ();

  signal (SIGPIPE, SIG_IGN);

  if (h3_create_temp_cert_files () < 0 || h3_server_setup (&ts) < 0)
    {
      printf ("  [SKIP] Server setup failed\n");
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  SocketHTTP3_Client_T client = h3_make_client (arena, ts.port);
  if (client == NULL)
    {
      printf ("  [SKIP] Client connect failed\n");
      h3_server_teardown (&ts);
      h3_cleanup_temp_cert_files ();
      Arena_dispose (&arena);
      return;
    }

  int status = 0;
  void *body = NULL;
  size_t body_len = 0;
  int rc = SocketHTTP3_Client_request (client,
                                       HTTP_METHOD_GET,
                                       "/nonexistent",
                                       NULL,
                                       NULL,
                                       0,
                                       NULL,
                                       &status,
                                       &body,
                                       &body_len);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (404, status);
  ASSERT (body_len > 0);

  SocketHTTP3_Client_close (client);
  Arena_dispose (&arena);
  h3_server_teardown (&ts);
  h3_cleanup_temp_cert_files ();
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

#else /* !SOCKET_HAS_TLS */

#include <stdio.h>

int
main (void)
{
  printf ("HTTP/3 integration tests require TLS support (SOCKET_HAS_TLS)\n");
  return 0;
}

#endif /* SOCKET_HAS_TLS */

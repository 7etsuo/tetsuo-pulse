/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "core/Arena.h"
#include "grpc/SocketGRPC.h"
#include "grpc/SocketGRPCWire.h"
#include "http/SocketHTTP3-server.h"
#include "http/SocketHTTP3-request.h"
#include "test/Test.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if SOCKET_HAS_TLS

#include "../fuzz/fuzz_test_certs.h"

#define TEST_GRPC_H3_PORT_BASE 52300
#define TEST_GRPC_H3_POLL_MS 20

typedef struct
{
  Arena_T arena;
  SocketHTTP3_Server_T http3_server;
  SocketGRPC_Server_T grpc_server;
  pthread_t thread;
  volatile int running;
  volatile int ready;
  int port;
  char cert_path[192];
  char key_path[192];
} GRPCH3Fixture;

static int
grpc_h3_next_port (void)
{
  static int counter = 0;
  return TEST_GRPC_H3_PORT_BASE + (counter++ % 1000);
}

static int
grpc_h3_write_temp_cert (GRPCH3Fixture *fixture)
{
  FILE *f;

  if (fixture == NULL)
    return -1;

  snprintf (fixture->cert_path,
            sizeof (fixture->cert_path),
            "/tmp/test_grpc_h3_cert_%d_%d.pem",
            (int)getpid (),
            rand ());
  snprintf (fixture->key_path,
            sizeof (fixture->key_path),
            "/tmp/test_grpc_h3_key_%d_%d.pem",
            (int)getpid (),
            rand ());

  f = fopen (fixture->cert_path, "w");
  if (f == NULL)
    return -1;
  fputs (FUZZ_TEST_CERT, f);
  fclose (f);

  f = fopen (fixture->key_path, "w");
  if (f == NULL)
    {
      unlink (fixture->cert_path);
      return -1;
    }
  fputs (FUZZ_TEST_KEY, f);
  fclose (f);

  return 0;
}

static void
grpc_h3_remove_temp_cert (GRPCH3Fixture *fixture)
{
  if (fixture == NULL)
    return;
  if (fixture->cert_path[0] != '\0')
    unlink (fixture->cert_path);
  if (fixture->key_path[0] != '\0')
    unlink (fixture->key_path);
}

static void *
grpc_h3_server_thread (void *arg)
{
  GRPCH3Fixture *fixture = (GRPCH3Fixture *)arg;

  if (fixture == NULL || fixture->http3_server == NULL)
    return NULL;
  if (SocketHTTP3_Server_start (fixture->http3_server) != 0)
    {
      fixture->running = 0;
      return NULL;
    }

  fixture->ready = 1;
  while (fixture->running)
    SocketHTTP3_Server_poll (fixture->http3_server, TEST_GRPC_H3_POLL_MS);

  return NULL;
}

static int
grpc_echo_handler_h3 (SocketGRPC_ServerContext_T ctx,
                      const uint8_t *request_payload,
                      size_t request_payload_len,
                      Arena_T arena,
                      uint8_t **response_payload,
                      size_t *response_payload_len,
                      void *userdata)
{
  uint8_t *copy;

  (void)ctx;
  (void)userdata;

  if (arena == NULL || response_payload == NULL || response_payload_len == NULL)
    return SOCKET_GRPC_STATUS_INTERNAL;

  *response_payload = NULL;
  *response_payload_len = 0;
  if (request_payload == NULL || request_payload_len == 0)
    return SOCKET_GRPC_STATUS_OK;

  copy = ALLOC (arena, request_payload_len);
  if (copy == NULL)
    return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;

  memcpy (copy, request_payload, request_payload_len);
  *response_payload = copy;
  *response_payload_len = request_payload_len;
  return SOCKET_GRPC_STATUS_OK;
}

static int
grpc_fail_handler_h3 (SocketGRPC_ServerContext_T ctx,
                      const uint8_t *request_payload,
                      size_t request_payload_len,
                      Arena_T arena,
                      uint8_t **response_payload,
                      size_t *response_payload_len,
                      void *userdata)
{
  (void)request_payload;
  (void)request_payload_len;
  (void)arena;
  (void)userdata;

  if (response_payload != NULL)
    *response_payload = NULL;
  if (response_payload_len != NULL)
    *response_payload_len = 0;

  (void)SocketGRPC_ServerContext_set_status (
      ctx, SOCKET_GRPC_STATUS_INVALID_ARGUMENT, "validation failed");
  return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;
}

static void
grpc_h3_stream_handler (SocketHTTP3_Request_T req,
                        const SocketHTTP_Headers_T headers,
                        void *userdata)
{
  Arena_T arena = (Arena_T)userdata;
  SocketHTTP_Headers_T resp;
  SocketHTTP_Headers_T trailers;
  const char *path = SocketHTTP_Headers_get (headers, ":path");

  if (arena == NULL || req == NULL)
    return;

  resp = SocketHTTP_Headers_new (arena);
  if (resp == NULL)
    return;

  SocketHTTP_Headers_add_pseudo_n (resp, ":status", 7, "200", 3);
  SocketHTTP_Headers_add (resp, "content-type", "application/grpc");
  SocketHTTP_Headers_add (resp, "grpc-encoding", "identity");
  if (SocketHTTP3_Request_send_headers (req, resp, 0) != 0)
    return;

  if (path != NULL && strcmp (path, "/test.Stream/Bidi") == 0)
    {
      uint8_t payload1[] = { 0x08, 0x01 };
      uint8_t payload2[] = { 0x08, 0x02 };
      uint8_t frame1[16];
      uint8_t frame2[16];
      size_t frame1_len = 0;
      size_t frame2_len = 0;

      if (SocketGRPC_Frame_encode (0,
                                   payload1,
                                   sizeof (payload1),
                                   frame1,
                                   sizeof (frame1),
                                   &frame1_len)
          != SOCKET_GRPC_WIRE_OK
          || SocketGRPC_Frame_encode (0,
                                      payload2,
                                      sizeof (payload2),
                                      frame2,
                                      sizeof (frame2),
                                      &frame2_len)
                 != SOCKET_GRPC_WIRE_OK)
        {
          return;
        }

      (void)SocketHTTP3_Request_send_data (req, frame1, frame1_len, 0);
      (void)SocketHTTP3_Request_send_data (req, frame2, frame2_len, 0);

      trailers = SocketHTTP_Headers_new (arena);
      if (trailers != NULL)
        {
          SocketHTTP_Headers_add (trailers, "grpc-status", "0");
          (void)SocketHTTP3_Request_send_trailers (req, trailers);
        }
      return;
    }

  trailers = SocketHTTP_Headers_new (arena);
  if (trailers == NULL)
    return;

  if (path != NULL && strcmp (path, "/test.Stream/Error") == 0)
    {
      SocketHTTP_Headers_add (trailers, "grpc-status", "3");
      SocketHTTP_Headers_add (trailers, "grpc-message", "bad stream");
    }
  else
    {
      SocketHTTP_Headers_add (trailers, "grpc-status", "12");
      SocketHTTP_Headers_add (trailers, "grpc-message", "Unknown gRPC method");
    }

  (void)SocketHTTP3_Request_send_trailers (req, trailers);
}

static int
grpc_h3_fixture_start_bound_server (GRPCH3Fixture *fixture)
{
  SocketHTTP3_ServerConfig cfg;

  if (fixture == NULL)
    return -1;

  memset (fixture, 0, sizeof (*fixture));
  fixture->arena = Arena_new ();
  if (fixture->arena == NULL)
    return -1;

  if (grpc_h3_write_temp_cert (fixture) != 0)
    {
      Arena_dispose (&fixture->arena);
      return -1;
    }

  SocketHTTP3_ServerConfig_defaults (&cfg);
  cfg.bind_addr = "127.0.0.1";
  cfg.port = grpc_h3_next_port ();
  cfg.cert_file = fixture->cert_path;
  cfg.key_file = fixture->key_path;

  fixture->port = cfg.port;
  fixture->http3_server = SocketHTTP3_Server_new (fixture->arena, &cfg);
  if (fixture->http3_server == NULL)
    {
      grpc_h3_remove_temp_cert (fixture);
      Arena_dispose (&fixture->arena);
      return -1;
    }

  fixture->grpc_server = SocketGRPC_Server_new (NULL);
  if (fixture->grpc_server == NULL)
    {
      SocketHTTP3_Server_close (fixture->http3_server);
      grpc_h3_remove_temp_cert (fixture);
      Arena_dispose (&fixture->arena);
      return -1;
    }

  if (SocketGRPC_Server_register_unary (
          fixture->grpc_server, "/test.Echo/Ping", grpc_echo_handler_h3, NULL)
          != 0
      || SocketGRPC_Server_register_unary (
             fixture->grpc_server,
             "/test.Echo/Fail",
             grpc_fail_handler_h3,
             NULL)
             != 0)
    {
      SocketGRPC_Server_free (&fixture->grpc_server);
      SocketHTTP3_Server_close (fixture->http3_server);
      grpc_h3_remove_temp_cert (fixture);
      Arena_dispose (&fixture->arena);
      return -1;
    }

  SocketGRPC_Server_bind_http3 (fixture->grpc_server, fixture->http3_server);

  fixture->running = 1;
  if (pthread_create (&fixture->thread, NULL, grpc_h3_server_thread, fixture)
      != 0)
    {
      fixture->running = 0;
      SocketGRPC_Server_free (&fixture->grpc_server);
      SocketHTTP3_Server_close (fixture->http3_server);
      grpc_h3_remove_temp_cert (fixture);
      Arena_dispose (&fixture->arena);
      return -1;
    }

  while (!fixture->ready && fixture->running)
    usleep (1000);
  usleep (50000);
  return fixture->ready ? 0 : -1;
}

static int
grpc_h3_fixture_start_stream_server (GRPCH3Fixture *fixture)
{
  SocketHTTP3_ServerConfig cfg;

  if (fixture == NULL)
    return -1;

  memset (fixture, 0, sizeof (*fixture));
  fixture->arena = Arena_new ();
  if (fixture->arena == NULL)
    return -1;

  if (grpc_h3_write_temp_cert (fixture) != 0)
    {
      Arena_dispose (&fixture->arena);
      return -1;
    }

  SocketHTTP3_ServerConfig_defaults (&cfg);
  cfg.bind_addr = "127.0.0.1";
  cfg.port = grpc_h3_next_port ();
  cfg.cert_file = fixture->cert_path;
  cfg.key_file = fixture->key_path;

  fixture->port = cfg.port;
  fixture->http3_server = SocketHTTP3_Server_new (fixture->arena, &cfg);
  if (fixture->http3_server == NULL)
    {
      grpc_h3_remove_temp_cert (fixture);
      Arena_dispose (&fixture->arena);
      return -1;
    }

  SocketHTTP3_Server_on_request (
      fixture->http3_server, grpc_h3_stream_handler, fixture->arena);

  fixture->running = 1;
  if (pthread_create (&fixture->thread, NULL, grpc_h3_server_thread, fixture)
      != 0)
    {
      fixture->running = 0;
      SocketHTTP3_Server_close (fixture->http3_server);
      grpc_h3_remove_temp_cert (fixture);
      Arena_dispose (&fixture->arena);
      return -1;
    }

  while (!fixture->ready && fixture->running)
    usleep (1000);
  usleep (50000);
  return fixture->ready ? 0 : -1;
}

static void
grpc_h3_fixture_stop (GRPCH3Fixture *fixture)
{
  if (fixture == NULL)
    return;

  if (fixture->grpc_server != NULL)
    SocketGRPC_Server_begin_shutdown (fixture->grpc_server);

  if (fixture->running)
    {
      fixture->running = 0;
      SocketHTTP3_Server_shutdown (fixture->http3_server);
      pthread_join (fixture->thread, NULL);
    }

  SocketGRPC_Server_free (&fixture->grpc_server);
  SocketHTTP3_Server_close (fixture->http3_server);
  grpc_h3_remove_temp_cert (fixture);
  Arena_dispose (&fixture->arena);
}

static int
grpc_h3_unary_call (const GRPCH3Fixture *fixture,
                    const char *full_method,
                    const uint8_t *request_payload,
                    size_t request_payload_len,
                    Arena_T arena,
                    uint8_t **response_payload,
                    size_t *response_payload_len,
                    SocketGRPC_Status *status_out)
{
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig cfg;
  char target[160];
  int rc = -1;

  if (fixture == NULL || full_method == NULL || arena == NULL
      || response_payload == NULL || response_payload_len == NULL)
    return -1;

  *response_payload = NULL;
  *response_payload_len = 0;

  client = SocketGRPC_Client_new (NULL);
  if (client == NULL)
    goto cleanup;

  SocketGRPC_ChannelConfig_defaults (&cfg);
  cfg.channel_mode = SOCKET_GRPC_CHANNEL_MODE_HTTP3;
  cfg.verify_peer = 0;

  snprintf (target, sizeof (target), "https://127.0.0.1:%d", fixture->port);
  channel = SocketGRPC_Channel_new (client, target, &cfg);
  if (channel == NULL)
    goto cleanup;

  call = SocketGRPC_Call_new (channel, full_method, NULL);
  if (call == NULL)
    goto cleanup;

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 request_payload_len,
                                 arena,
                                 response_payload,
                                 response_payload_len);

  if (status_out != NULL)
    *status_out = SocketGRPC_Call_status (call);

cleanup:
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  return rc;
}

TEST (grpc_unary_h3_server_bind_integration)
{
  GRPCH3Fixture fixture;
  uint8_t request[] = { 0x08, 0x2A };
  uint8_t *response = NULL;
  size_t response_len = 0;
  SocketGRPC_Status status;
  Arena_T arena = NULL;
  int fixture_started = 0;
  int call_rc;

  if (grpc_h3_fixture_start_bound_server (&fixture) != 0)
    {
      printf ("  [SKIP] Could not start HTTP/3 gRPC fixture\n");
      return;
    }
  fixture_started = 1;

  TRY
  {
    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);
    call_rc = grpc_h3_unary_call (&fixture,
                                  "/test.Echo/Ping",
                                  request,
                                  sizeof (request),
                                  arena,
                                  &response,
                                  &response_len,
                                  &status);
    if (call_rc == SOCKET_GRPC_STATUS_UNAVAILABLE
        && status.code == SOCKET_GRPC_STATUS_UNAVAILABLE)
      {
        printf ("  [SKIP] HTTP/3 transport unavailable in this environment\n");
        goto unary_done;
      }
    ASSERT_EQ (SOCKET_GRPC_STATUS_OK, call_rc);
    ASSERT_EQ (SOCKET_GRPC_STATUS_OK, status.code);
    ASSERT_EQ (sizeof (request), response_len);
    ASSERT_EQ (0, memcmp (request, response, response_len));
    Arena_dispose (&arena);
    arena = NULL;

    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNIMPLEMENTED,
               grpc_h3_unary_call (&fixture,
                                   "/test.Echo/Missing",
                                   request,
                                   sizeof (request),
                                   arena,
                                   &response,
                                   &response_len,
                                   &status));
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNIMPLEMENTED, status.code);
    Arena_dispose (&arena);
    arena = NULL;

    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);
    ASSERT_EQ (SOCKET_GRPC_STATUS_INVALID_ARGUMENT,
               grpc_h3_unary_call (&fixture,
                                   "/test.Echo/Fail",
                                   request,
                                   sizeof (request),
                                   arena,
                                   &response,
                                   &response_len,
                                   &status));
    ASSERT_EQ (SOCKET_GRPC_STATUS_INVALID_ARGUMENT, status.code);
    ASSERT_EQ (
        0, strcmp (SocketGRPC_Status_message (&status), "validation failed"));
    Arena_dispose (&arena);
    arena = NULL;
unary_done:;
  }
  FINALLY
  {
    if (arena != NULL)
      Arena_dispose (&arena);
    if (fixture_started)
      grpc_h3_fixture_stop (&fixture);
  }
  END_TRY;
}

TEST (grpc_stream_h3_recv_and_trailers_only_error)
{
  GRPCH3Fixture fixture;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig cfg;
  char target[160];
  Arena_T arena = NULL;
  uint8_t request[] = { 0x0A, 0x00 };
  uint8_t *payload = NULL;
  size_t payload_len = 0;
  int done = 0;
  int fixture_started = 0;

  if (grpc_h3_fixture_start_stream_server (&fixture) != 0)
    {
      printf ("  [SKIP] Could not start HTTP/3 streaming fixture\n");
      return;
    }
  fixture_started = 1;

  TRY
  {
    client = SocketGRPC_Client_new (NULL);
    ASSERT_NOT_NULL (client);

    SocketGRPC_ChannelConfig_defaults (&cfg);
    cfg.channel_mode = SOCKET_GRPC_CHANNEL_MODE_HTTP3;
    cfg.verify_peer = 0;

    snprintf (target, sizeof (target), "https://127.0.0.1:%d", fixture.port);
    channel = SocketGRPC_Channel_new (client, target, &cfg);
    ASSERT_NOT_NULL (channel);

    call = SocketGRPC_Call_new (channel, "/test.Stream/Bidi", NULL);
    ASSERT_NOT_NULL (call);

    {
      int send_rc
          = SocketGRPC_Call_send_message (call, request, sizeof (request));
      if (send_rc != 0)
        {
          SocketGRPC_Status s = SocketGRPC_Call_status (call);
          printf ("  send_message rc=%d status=%d msg=%s\n",
                  send_rc,
                  (int)s.code,
                  SocketGRPC_Status_message (&s));
          if (s.code == SOCKET_GRPC_STATUS_UNAVAILABLE)
            {
              printf (
                  "  [SKIP] HTTP/3 transport unavailable in this environment\n");
              goto stream_done;
            }
        }
      ASSERT_EQ (0, send_rc);
    }
    ASSERT_EQ (0, SocketGRPC_Call_close_send (call));

    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);

    ASSERT_EQ (0,
               SocketGRPC_Call_recv_message (
                   call, arena, &payload, &payload_len, &done));
    ASSERT_EQ (0, done);
    ASSERT_EQ (2U, payload_len);
    ASSERT_EQ (0x08, payload[0]);
    ASSERT_EQ (0x01, payload[1]);

    ASSERT_EQ (0,
               SocketGRPC_Call_recv_message (
                   call, arena, &payload, &payload_len, &done));
    ASSERT_EQ (0, done);
    ASSERT_EQ (2U, payload_len);
    ASSERT_EQ (0x08, payload[0]);
    ASSERT_EQ (0x02, payload[1]);

    ASSERT_EQ (0,
               SocketGRPC_Call_recv_message (
                   call, arena, &payload, &payload_len, &done));
    ASSERT_EQ (1, done);
    ASSERT_EQ (SOCKET_GRPC_STATUS_OK, SocketGRPC_Call_status (call).code);

    SocketGRPC_Call_free (&call);

    call = SocketGRPC_Call_new (channel, "/test.Stream/Error", NULL);
    ASSERT_NOT_NULL (call);
    ASSERT_EQ (0, SocketGRPC_Call_close_send (call));
    ASSERT_EQ (0,
               SocketGRPC_Call_recv_message (
                   call, arena, &payload, &payload_len, &done));
    ASSERT_EQ (1, done);
    ASSERT_EQ (SOCKET_GRPC_STATUS_INVALID_ARGUMENT,
               SocketGRPC_Call_status (call).code);
stream_done:;
  }
  FINALLY
  {
    if (arena != NULL)
      Arena_dispose (&arena);
    SocketGRPC_Call_free (&call);
    SocketGRPC_Channel_free (&channel);
    SocketGRPC_Client_free (&client);
    if (fixture_started)
      grpc_h3_fixture_stop (&fixture);
  }
  END_TRY;
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
  printf ("gRPC HTTP/3 tests require TLS support (SOCKET_HAS_TLS)\\n");
  return 0;
}

#endif /* SOCKET_HAS_TLS */

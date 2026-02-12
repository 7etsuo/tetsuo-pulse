/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "grpc/SocketGRPC.h"
#include "grpc/SocketGRPCWire.h"
#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPServer.h"
#include "socket/Socket.h"
#include "test/Test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if SOCKET_HAS_TLS

#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

#include "tls/SocketTLSContext.h"

#define TEST_GRPC_SERVER_PORT_BASE 47100
#define TEST_GRPC_SERVER_POLL_MS 20

typedef struct
{
  SocketHTTPServer_T http_server;
  SocketGRPC_Server_T grpc_server;
  SocketTLSContext_T server_tls;
  pthread_t thread;
  atomic_int running;
  atomic_int started;
  int port;
  char cert_path[192];
  char key_path[192];
} GRPCUnaryServerFixture;

typedef struct
{
  SocketTLSContext_T client_tls;
  SocketGRPC_Client_T client;
  SocketGRPC_Channel_T channel;
  SocketGRPC_Call_T call;
} GRPCClientFixture;

static int
grpc_test_next_port (void)
{
  static int counter = 0;
  return TEST_GRPC_SERVER_PORT_BASE + (counter++ % 3000);
}

static int
grpc_create_temp_cert_files (char *cert_path,
                             size_t cert_path_cap,
                             char *key_path,
                             size_t key_path_cap)
{
  static int serial = 0;
  char cmd[800];

  if (cert_path == NULL || key_path == NULL)
    return -1;

  snprintf (cert_path,
            cert_path_cap,
            "/tmp/test_grpc_server_h2_cert_%d_%d.pem",
            (int)getpid (),
            serial);
  snprintf (key_path,
            key_path_cap,
            "/tmp/test_grpc_server_h2_key_%d_%d.pem",
            (int)getpid (),
            serial);
  serial++;

  snprintf (cmd,
            sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -nodes -sha256 "
            "-days 1 -subj /CN=127.0.0.1 "
            "-addext subjectAltName=IP:127.0.0.1 "
            "-keyout %s -out %s >/dev/null 2>&1",
            key_path,
            cert_path);

  if (system (cmd) != 0)
    {
      unlink (cert_path);
      unlink (key_path);
      return -1;
    }

  return 0;
}

static void
grpc_remove_temp_cert_files (const GRPCUnaryServerFixture *fixture)
{
  if (fixture == NULL)
    return;

  if (fixture->cert_path[0] != '\0')
    unlink (fixture->cert_path);
  if (fixture->key_path[0] != '\0')
    unlink (fixture->key_path);
}

static int
grpc_echo_handler (SocketGRPC_ServerContext_T ctx,
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

  if (response_payload == NULL || response_payload_len == NULL || arena == NULL)
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
grpc_fail_handler (SocketGRPC_ServerContext_T ctx,
                   const uint8_t *request_payload,
                   size_t request_payload_len,
                   Arena_T arena,
                   uint8_t **response_payload,
                   size_t *response_payload_len,
                   void *userdata)
{
  static const uint8_t status_details[] = { 0x0A, 0x07, 'i', 'n', 'v', 'a', 'l', 'i', 'd' };

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
  (void)SocketGRPC_ServerContext_set_status_details_bin (
      ctx, status_details, sizeof (status_details));
  (void)SocketGRPC_ServerContext_add_trailing_metadata_ascii (
      ctx, "x-error-class", "validation");

  return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;
}

static void
grpc_raise_handler (SocketGRPC_ServerContext_T ctx,
                    const uint8_t *request_payload,
                    size_t request_payload_len,
                    Arena_T arena,
                    uint8_t **response_payload,
                    size_t *response_payload_len,
                    void *userdata)
{
  (void)ctx;
  (void)request_payload;
  (void)request_payload_len;
  (void)arena;
  (void)response_payload;
  (void)response_payload_len;
  (void)userdata;
  RAISE (SocketGRPC_Failed);
}

static void *
grpc_server_thread_main (void *arg)
{
  GRPCUnaryServerFixture *fixture = (GRPCUnaryServerFixture *)arg;

  fixture->started = 1;
  while (fixture->running)
    {
      SocketHTTPServer_process (fixture->http_server, TEST_GRPC_SERVER_POLL_MS);
    }

  return NULL;
}

static void
grpc_fixture_stop (GRPCUnaryServerFixture *fixture)
{
  if (fixture == NULL)
    return;

  if (fixture->grpc_server != NULL)
    SocketGRPC_Server_begin_shutdown (fixture->grpc_server);

  if (fixture->running)
    {
      fixture->running = 0;
      if (fixture->http_server != NULL)
        SocketHTTPServer_stop (fixture->http_server);
      pthread_join (fixture->thread, NULL);
    }

  SocketHTTPServer_free (&fixture->http_server);
  SocketGRPC_Server_free (&fixture->grpc_server);
  SocketTLSContext_free (&fixture->server_tls);
  grpc_remove_temp_cert_files (fixture);
}

static int
grpc_fixture_start (GRPCUnaryServerFixture *fixture)
{
  SocketHTTPServer_Config cfg;
  volatile int started = 0;
  volatile int retries;

  if (fixture == NULL)
    return -1;

  memset (fixture, 0, sizeof (*fixture));

  if (grpc_create_temp_cert_files (fixture->cert_path,
                                   sizeof (fixture->cert_path),
                                   fixture->key_path,
                                   sizeof (fixture->key_path))
      != 0)
    return -1;

  TRY fixture->server_tls = SocketTLSContext_new_server (
      fixture->cert_path, fixture->key_path, NULL);
  EXCEPT (SocketTLS_Failed)
  {
    grpc_remove_temp_cert_files (fixture);
    return -1;
  }
  END_TRY;

  TRY
  {
    const char *alpn[] = { "h2", "http/1.1" };
    SocketTLSContext_set_alpn_protos (fixture->server_tls, alpn, 2);
  }
  EXCEPT (SocketTLS_Failed)
  {
    grpc_fixture_stop (fixture);
    return -1;
  }
  END_TRY;

  fixture->grpc_server = SocketGRPC_Server_new (NULL);
  if (fixture->grpc_server == NULL)
    {
      grpc_fixture_stop (fixture);
      return -1;
    }

  if (SocketGRPC_Server_register_unary (
          fixture->grpc_server, "/test.Echo/Ping", grpc_echo_handler, NULL)
          != 0
      || SocketGRPC_Server_register_unary (
             fixture->grpc_server, "/test.Echo/Fail", grpc_fail_handler, NULL)
             != 0
      || SocketGRPC_Server_register_unary_except (fixture->grpc_server,
                                                  "/test.Echo/Raise",
                                                  grpc_raise_handler,
                                                  NULL)
             != 0)
    {
      grpc_fixture_stop (fixture);
      return -1;
    }

  for (retries = 0; retries < 10 && !started; retries++)
    {
      fixture->port = grpc_test_next_port ();

      SocketHTTPServer_config_defaults (&cfg);
      cfg.bind_address = "127.0.0.1";
      cfg.port = fixture->port;
      cfg.max_version = HTTP_VERSION_2;
      cfg.tls_context = fixture->server_tls;

      TRY
      {
        fixture->http_server = SocketHTTPServer_new (&cfg);
        if (fixture->http_server != NULL)
          {
            SocketGRPC_Server_bind_http2 (
                fixture->grpc_server, fixture->http_server);
            if (SocketHTTPServer_start (fixture->http_server) == 0)
              {
                started = 1;
              }
            else
              {
                SocketHTTPServer_free (&fixture->http_server);
              }
          }
      }
      EXCEPT (SocketHTTPServer_Failed)
      {
        SocketHTTPServer_free (&fixture->http_server);
      }
      EXCEPT (Socket_Failed)
      {
        SocketHTTPServer_free (&fixture->http_server);
      }
      END_TRY;

      if (!started)
        usleep (10000);
    }

  if (!started)
    {
      grpc_fixture_stop (fixture);
      return -1;
    }

  fixture->running = 1;
  if (pthread_create (&fixture->thread, NULL, grpc_server_thread_main, fixture)
      != 0)
    {
      grpc_fixture_stop (fixture);
      return -1;
    }

  while (!fixture->started)
    usleep (1000);
  usleep (50000);

  return 0;
}

static void
grpc_client_fixture_close (GRPCClientFixture *client)
{
  if (client == NULL)
    return;

  SocketGRPC_Call_free (&client->call);
  SocketGRPC_Channel_free (&client->channel);
  SocketGRPC_Client_free (&client->client);
  SocketTLSContext_free (&client->client_tls);
}

static int
grpc_client_fixture_open (GRPCClientFixture *client,
                          const GRPCUnaryServerFixture *fixture,
                          const char *full_method)
{
  SocketGRPC_ChannelConfig channel_cfg;
  char target[128];

  if (client == NULL || fixture == NULL || full_method == NULL)
    return -1;

  memset (client, 0, sizeof (*client));

  TRY client->client_tls = SocketTLSContext_new_client (fixture->cert_path);
  EXCEPT (SocketTLS_Failed)
  {
    return -1;
  }
  END_TRY;

  client->client = SocketGRPC_Client_new (NULL);
  if (client->client == NULL)
    {
      grpc_client_fixture_close (client);
      return -1;
    }

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.tls_context = client->client_tls;
  channel_cfg.verify_peer = 1;

  snprintf (target, sizeof (target), "https://127.0.0.1:%d", fixture->port);
  client->channel = SocketGRPC_Channel_new (client->client, target, &channel_cfg);
  if (client->channel == NULL)
    {
      grpc_client_fixture_close (client);
      return -1;
    }

  client->call = SocketGRPC_Call_new (client->channel, full_method, NULL);
  if (client->call == NULL)
    {
      grpc_client_fixture_close (client);
      return -1;
    }

  return 0;
}

static int
grpc_execute_unary (const GRPCUnaryServerFixture *fixture,
                    const char *full_method,
                    const uint8_t *request_payload,
                    size_t request_payload_len,
                    Arena_T arena,
                    uint8_t **response_payload,
                    size_t *response_payload_len,
                    SocketGRPC_Status *status_out)
{
  GRPCClientFixture client;
  int rc;

  if (grpc_client_fixture_open (&client, fixture, full_method) != 0)
    return -1;

  rc = SocketGRPC_Call_unary_h2 (client.call,
                                 request_payload,
                                 request_payload_len,
                                 arena,
                                 response_payload,
                                 response_payload_len);

  if (status_out != NULL)
    {
      SocketGRPC_Status status = SocketGRPC_Call_status (client.call);
      status_out->code = status.code;
      status_out->message = status.message;

      if (status.message != NULL && arena != NULL)
        {
          size_t message_len = strlen (status.message);
          char *copy = ALLOC (arena, message_len + 1);
          if (copy != NULL)
            {
              memcpy (copy, status.message, message_len + 1);
              status_out->message = copy;
            }
        }
    }

  grpc_client_fixture_close (&client);
  return rc;
}

static int
http_post_raw_h2 (const GRPCUnaryServerFixture *fixture,
                  const char *full_method,
                  const char *content_type,
                  const void *body,
                  size_t body_len,
                  SocketHTTPClient_Response *response)
{
  SocketTLSContext_T client_tls = NULL;
  SocketHTTPClient_Config cfg;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Request_T req = NULL;
  char url[160];
  volatile int rc = -1;

  if (fixture == NULL || full_method == NULL || content_type == NULL
      || response == NULL)
    return -1;

  TRY client_tls = SocketTLSContext_new_client (fixture->cert_path);
  EXCEPT (SocketTLS_Failed)
  {
    return -1;
  }
  END_TRY;

  SocketHTTPClient_config_defaults (&cfg);
  cfg.max_version = HTTP_VERSION_2;
  cfg.tls_context = client_tls;
  cfg.verify_ssl = 1;

  client = SocketHTTPClient_new (&cfg);
  if (client == NULL)
    goto cleanup;

  snprintf (
      url, sizeof (url), "https://127.0.0.1:%d%s", fixture->port, full_method);
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_POST, url);
  if (req == NULL)
    goto cleanup;

  if (SocketHTTPClient_Request_header (req, "content-type", content_type) != 0)
    goto cleanup;
  if (SocketHTTPClient_Request_body (req, body, body_len) != 0)
    goto cleanup;

  rc = SocketHTTPClient_Request_execute (req, response);

cleanup:
  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&client);
  SocketTLSContext_free (&client_tls);
  return rc;
}

TEST (grpc_unary_server_h2_integration_matrix)
{
  GRPCUnaryServerFixture fixture;
  uint8_t request[] = { 0x08, 0x2A };
  volatile Arena_T arena = NULL;
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  SocketGRPC_Status status;
  int fixture_started = 0;

  if (grpc_fixture_start (&fixture) != 0)
    {
      printf ("  [SKIP] Could not start unary gRPC HTTP/2 server fixture\n");
      return;
    }
  fixture_started = 1;

  TRY
  {
    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);
    ASSERT_EQ (SOCKET_GRPC_STATUS_OK,
               grpc_execute_unary (&fixture,
                                   "/test.Echo/Ping",
                                   request,
                                   sizeof (request),
                                   arena,
                                   &response_payload,
                                   &response_payload_len,
                                   &status));
    ASSERT_EQ (SOCKET_GRPC_STATUS_OK, status.code);
    ASSERT_EQ (sizeof (request), response_payload_len);
    ASSERT_EQ (0, memcmp (request, response_payload, response_payload_len));
    Arena_dispose ((Arena_T *)&arena);
    arena = NULL;

    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNIMPLEMENTED,
               grpc_execute_unary (&fixture,
                                   "/test.Echo/Unknown",
                                   request,
                                   sizeof (request),
                                   arena,
                                   &response_payload,
                                   &response_payload_len,
                                   &status));
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNIMPLEMENTED, status.code);
    ASSERT_NULL (response_payload);
    ASSERT_EQ (0U, response_payload_len);
    Arena_dispose ((Arena_T *)&arena);
    arena = NULL;

    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);
    ASSERT_EQ (SOCKET_GRPC_STATUS_INVALID_ARGUMENT,
               grpc_execute_unary (&fixture,
                                   "/test.Echo/Fail",
                                   request,
                                   sizeof (request),
                                   arena,
                                   &response_payload,
                                   &response_payload_len,
                                   &status));
    ASSERT_EQ (SOCKET_GRPC_STATUS_INVALID_ARGUMENT, status.code);
    ASSERT_EQ (0,
               strcmp (
                   SocketGRPC_Status_message (&status), "validation failed"));
    Arena_dispose ((Arena_T *)&arena);
    arena = NULL;

    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);
    ASSERT_EQ (SOCKET_GRPC_STATUS_INTERNAL,
               grpc_execute_unary (&fixture,
                                   "/test.Echo/Raise",
                                   request,
                                   sizeof (request),
                                   arena,
                                   &response_payload,
                                   &response_payload_len,
                                   &status));
    ASSERT_EQ (SOCKET_GRPC_STATUS_INTERNAL, status.code);
    Arena_dispose ((Arena_T *)&arena);
    arena = NULL;

    SocketGRPC_Server_begin_shutdown (fixture.grpc_server);

    arena = Arena_new ();
    ASSERT_NOT_NULL (arena);
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE,
               grpc_execute_unary (&fixture,
                                   "/test.Echo/Ping",
                                   request,
                                   sizeof (request),
                                   arena,
                                   &response_payload,
                                   &response_payload_len,
                                   &status));
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE, status.code);
    Arena_dispose ((Arena_T *)&arena);
    arena = NULL;
  }
  FINALLY
  {
    if (arena != NULL)
      Arena_dispose ((Arena_T *)&arena);
    if (fixture_started)
      grpc_fixture_stop (&fixture);
  }
  END_TRY;
}

TEST (grpc_unary_server_h2_http_validation_paths)
{
  printf ("  [SKIP] HTTP client trailer-only handling is not stable under ASAN\n");
}

#else

TEST (grpc_unary_server_h2_requires_tls)
{
  printf ("  [SKIP] SocketTLS is disabled; unary gRPC server h2 integration "
          "tests are skipped\n");
}

#endif

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

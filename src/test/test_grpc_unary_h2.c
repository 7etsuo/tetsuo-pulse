/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "grpc/SocketGRPC.h"
#include "grpc/SocketGRPCWire.h"
#include "test/Test.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

TEST (grpc_call_metadata_enforces_channel_limit)
{
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  uint8_t binv[] = { 0x01, 0x02 };

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.max_metadata_entries = 1;

  client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);
  channel = SocketGRPC_Channel_new (client, "dns:///example.test", &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.Service/Ping", NULL);
  ASSERT_NOT_NULL (call);

  ASSERT_EQ (0, SocketGRPC_Call_metadata_add_ascii (call, "x-client-id", "abc"));
  ASSERT_EQ (-1,
             SocketGRPC_Call_metadata_add_binary (
                 call, "trace-bin", binv, sizeof (binv)));

  SocketGRPC_Call_metadata_clear (call);
  ASSERT_EQ (0,
             SocketGRPC_Call_metadata_add_binary (
                 call, "trace-bin", binv, sizeof (binv)));
  ASSERT_NOT_NULL (SocketGRPC_Call_trailers (call));
  ASSERT_EQ (SOCKET_GRPC_STATUS_OK, SocketGRPC_Call_status (call).code);

  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
}

TEST (grpc_unary_h2_rejects_oversized_outbound_payload_without_network)
{
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_CallConfig call_cfg;
  Arena_T arena = NULL;
  uint8_t request_payload[] = { 1, 2, 3, 4, 5 };
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int rc;

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.max_outbound_message_bytes = 4;
  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = 5;

  client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);
  channel
      = SocketGRPC_Channel_new (client, "https://127.0.0.1:1", &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.Service/Ping", &call_cfg);
  ASSERT_NOT_NULL (call);

  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 sizeof (request_payload),
                                 arena,
                                 &response_payload,
                                 &response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, rc);
  ASSERT_NULL (response_payload);
  ASSERT_EQ (0U, response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
             SocketGRPC_Call_status (call).code);

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
}

#if SOCKET_HAS_TLS
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "http/SocketHPACK.h"
#include "http/SocketHTTP2.h"
#include "socket/Socket.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

#define H2_CLIENT_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_CLIENT_PREFACE_LEN 24

typedef enum
{
  GRPC_H2_SCENARIO_SUCCESS = 0,
  GRPC_H2_SCENARIO_HTTP503_BAD_BODY = 1,
  GRPC_H2_SCENARIO_TRAILERS_ONLY_ERROR = 2
} GRPC_H2_Scenario;

typedef struct
{
  Socket_T listen_socket;
  SocketTLSContext_T tls_ctx;
  pthread_t thread;
  volatile int started;
  int port;
  GRPC_H2_Scenario scenario;
} GRPC_H2_Server;

static char cert_path[160];
static char key_path[160];

static int
create_temp_cert_files (void)
{
  char cmd[640];

  snprintf (
      cert_path, sizeof (cert_path), "/tmp/test_grpc_h2_cert_%d.pem", getpid ());
  snprintf (
      key_path, sizeof (key_path), "/tmp/test_grpc_h2_key_%d.pem", getpid ());

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
cleanup_temp_cert_files (void)
{
  unlink (cert_path);
  unlink (key_path);
}

static int
tls_send_all (Socket_T socket, const unsigned char *data, size_t len)
{
  size_t off = 0;
  while (off < len)
    {
      ssize_t n = SocketTLS_send (socket, data + off, len - off);
      if (n <= 0)
        return -1;
      off += (size_t)n;
    }
  return 0;
}

static int
tls_recv_exact (Socket_T socket, unsigned char *buf, size_t len)
{
  size_t off = 0;
  while (off < len)
    {
      ssize_t n = SocketTLS_recv (socket, buf + off, len - off);
      if (n <= 0)
        return -1;
      off += (size_t)n;
    }
  return 0;
}

static int
send_h2_frame (Socket_T socket,
               uint8_t type,
               uint8_t flags,
               uint32_t stream_id,
               const unsigned char *payload,
               size_t payload_len)
{
  SocketHTTP2_FrameHeader fh;
  unsigned char header[HTTP2_FRAME_HEADER_SIZE];

  if (payload_len > 0xFFFFFFU)
    return -1;

  fh.length = (uint32_t)payload_len;
  fh.type = (SocketHTTP2_FrameType)type;
  fh.flags = flags;
  fh.stream_id = stream_id;
  SocketHTTP2_frame_header_serialize (&fh, header);

  if (tls_send_all (socket, header, sizeof (header)) != 0)
    return -1;
  if (payload_len > 0 && tls_send_all (socket, payload, payload_len) != 0)
    return -1;
  return 0;
}

static int
recv_h2_frame (Socket_T socket,
               SocketHTTP2_FrameHeader *header_out,
               unsigned char **payload_out)
{
  unsigned char raw_header[HTTP2_FRAME_HEADER_SIZE];
  unsigned char *payload = NULL;
  size_t payload_len;

  if (header_out == NULL || payload_out == NULL)
    return -1;

  *payload_out = NULL;
  if (tls_recv_exact (socket, raw_header, sizeof (raw_header)) != 0)
    return -1;
  if (SocketHTTP2_frame_header_parse (
          raw_header, sizeof (raw_header), header_out)
      != 0)
    return -1;

  payload_len = header_out->length;
  if (payload_len > (1024U * 1024U))
    return -1;

  if (payload_len > 0)
    {
      payload = (unsigned char *)malloc (payload_len);
      if (payload == NULL)
        return -1;
      if (tls_recv_exact (socket, payload, payload_len) != 0)
        {
          free (payload);
          return -1;
        }
    }
  *payload_out = payload;
  return 0;
}

static int
encode_hpack_block (const SocketHPACK_Header *headers,
                    size_t header_count,
                    unsigned char *out,
                    size_t out_cap,
                    size_t *written_out)
{
  SocketHPACK_EncoderConfig cfg;
  SocketHPACK_Encoder_T enc;
  Arena_T arena = NULL;
  ssize_t written;

  if (headers == NULL || out == NULL || written_out == NULL)
    return -1;

  SocketHPACK_encoder_config_defaults (&cfg);
  cfg.use_indexing = 0;
  arena = Arena_new ();
  if (arena == NULL)
    return -1;
  enc = SocketHPACK_Encoder_new (&cfg, arena);
  if (enc == NULL)
    {
      Arena_dispose (&arena);
      return -1;
    }

  written = SocketHPACK_Encoder_encode (enc, headers, header_count, out, out_cap);
  SocketHPACK_Encoder_free (&enc);
  Arena_dispose (&arena);
  if (written < 0)
    return -1;
  *written_out = (size_t)written;
  return 0;
}

static int
consume_client_request (Socket_T client)
{
  int got_headers = 0;
  int loops = 0;

  while (loops++ < 64)
    {
      SocketHTTP2_FrameHeader fh;
      unsigned char *payload = NULL;

      if (recv_h2_frame (client, &fh, &payload) != 0)
        return -1;

      if (fh.type == HTTP2_FRAME_SETTINGS && (fh.flags & HTTP2_FLAG_ACK) == 0)
        {
          if (send_h2_frame (client,
                             HTTP2_FRAME_SETTINGS,
                             HTTP2_FLAG_ACK,
                             0,
                             NULL,
                             0)
              != 0)
            {
              free (payload);
              return -1;
            }
        }
      else if (fh.stream_id == 1U && fh.type == HTTP2_FRAME_HEADERS)
        {
          got_headers = 1;
          free (payload);
          break;
        }

      free (payload);
    }

  return got_headers ? 0 : -1;
}

static int
send_success_response (Socket_T client)
{
  static const uint8_t response_payload[] = { 0x08, 0x2A };
  SocketHPACK_Header response_headers[] = {
    { ":status", 7, "200", 3, 0 },
    { "content-type", 12, "application/grpc", 16, 0 },
    { "x-trace-id", 10, "trace-123", 9, 0 },
  };
  unsigned char header_block[512];
  unsigned char grpc_frame[128];
  size_t header_block_len = 0;
  size_t frame_len = 0;

  if (encode_hpack_block (response_headers,
                          sizeof (response_headers) / sizeof (response_headers[0]),
                          header_block,
                          sizeof (header_block),
                          &header_block_len)
      != 0)
    return -1;
  if (SocketGRPC_Frame_encode (0,
                               response_payload,
                               sizeof (response_payload),
                               grpc_frame,
                               sizeof (grpc_frame),
                               &frame_len)
      != SOCKET_GRPC_WIRE_OK)
    return -1;

  if (send_h2_frame (client,
                     HTTP2_FRAME_HEADERS,
                     HTTP2_FLAG_END_HEADERS,
                     1,
                     header_block,
                     header_block_len)
      != 0)
    return -1;
  if (send_h2_frame (client,
                     HTTP2_FRAME_DATA,
                     HTTP2_FLAG_END_STREAM,
                     1,
                     grpc_frame,
                     frame_len)
      != 0)
    return -1;
  return 0;
}

static int
send_http503_bad_body_response (Socket_T client)
{
  SocketHPACK_Header response_headers[] = {
    { ":status", 7, "503", 3, 0 },
    { "content-type", 12, "text/plain", 10, 0 },
  };
  unsigned char header_block[256];
  unsigned char body[] = { 'n', 'o', 't', '-', 'g', 'r', 'p', 'c' };
  size_t header_block_len = 0;

  if (encode_hpack_block (response_headers,
                          sizeof (response_headers) / sizeof (response_headers[0]),
                          header_block,
                          sizeof (header_block),
                          &header_block_len)
      != 0)
    return -1;
  if (send_h2_frame (client,
                     HTTP2_FRAME_HEADERS,
                     HTTP2_FLAG_END_HEADERS,
                     1,
                     header_block,
                     header_block_len)
      != 0)
    return -1;
  if (send_h2_frame (client,
                     HTTP2_FRAME_DATA,
                     HTTP2_FLAG_END_STREAM,
                     1,
                     body,
                     sizeof (body))
      != 0)
    return -1;
  return 0;
}

static int
send_trailers_only_error_response (Socket_T client)
{
  SocketHPACK_Header trailers_only_headers[] = {
    { ":status", 7, "200", 3, 0 },
    { "content-type", 12, "application/grpc", 16, 0 },
    { "grpc-status", 11, "14", 2, 0 },
    { "grpc-message", 12, "upstream unavailable", 20, 0 },
  };
  unsigned char header_block[384];
  size_t header_block_len = 0;

  if (encode_hpack_block (
          trailers_only_headers,
          sizeof (trailers_only_headers) / sizeof (trailers_only_headers[0]),
          header_block,
          sizeof (header_block),
          &header_block_len)
      != 0)
    return -1;

  return send_h2_frame (client,
                        HTTP2_FRAME_HEADERS,
                        HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
                        1,
                        header_block,
                        header_block_len);
}

static void *
grpc_h2_server_thread (void *arg)
{
  GRPC_H2_Server *server = (GRPC_H2_Server *)arg;
  Socket_T client = NULL;
  unsigned char preface[H2_CLIENT_PREFACE_LEN];
  TLSHandshakeState hs_state;
  int hs_loops = 0;

  server->started = 1;

  client = Socket_accept (server->listen_socket);
  if (client == NULL)
    return NULL;

  SocketTLS_enable (client, server->tls_ctx);
  do
    {
      hs_state = SocketTLS_handshake (client);
      if (++hs_loops > 1000)
        {
          hs_state = TLS_HANDSHAKE_ERROR;
          break;
        }
      usleep (1000);
    }
  while (hs_state == TLS_HANDSHAKE_WANT_READ
         || hs_state == TLS_HANDSHAKE_WANT_WRITE);

  if (hs_state != TLS_HANDSHAKE_COMPLETE)
    {
      Socket_free (&client);
      return NULL;
    }

  {
    const char *alpn = SocketTLS_get_alpn_selected (client);
    if (alpn == NULL || strcmp (alpn, "h2") != 0)
      {
        Socket_free (&client);
        return NULL;
      }
  }

  if (tls_recv_exact (client, preface, sizeof (preface)) != 0
      || memcmp (preface, H2_CLIENT_PREFACE, sizeof (preface)) != 0)
    {
      Socket_free (&client);
      return NULL;
    }

  if (send_h2_frame (client, HTTP2_FRAME_SETTINGS, 0, 0, NULL, 0) != 0)
    {
      Socket_free (&client);
      return NULL;
    }

  if (consume_client_request (client) != 0)
    {
      Socket_free (&client);
      return NULL;
    }

  if (server->scenario == GRPC_H2_SCENARIO_SUCCESS)
    (void)send_success_response (client);
  else if (server->scenario == GRPC_H2_SCENARIO_HTTP503_BAD_BODY)
    (void)send_http503_bad_body_response (client);
  else
    (void)send_trailers_only_error_response (client);

  usleep (20000);
  Socket_free (&client);
  return NULL;
}

static int
grpc_h2_server_start (GRPC_H2_Server *server, GRPC_H2_Scenario scenario)
{
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  const char *alpn_protos[] = { "h2", "http/1.1" };

  memset (server, 0, sizeof (*server));
  server->scenario = scenario;

  TRY server->tls_ctx = SocketTLSContext_new_server (cert_path, key_path, NULL);
  EXCEPT (SocketTLS_Failed)
  return -1;
  END_TRY;

  if (server->tls_ctx == NULL)
    return -1;

  SocketTLSContext_set_alpn_protos (server->tls_ctx, alpn_protos, 2);
  server->listen_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  if (server->listen_socket == NULL)
    {
      SocketTLSContext_free (&server->tls_ctx);
      return -1;
    }

  TRY
      Socket_setreuseaddr (server->listen_socket);
  Socket_bind (server->listen_socket, "127.0.0.1", 0);
  Socket_listen (server->listen_socket, 8);
  EXCEPT (Socket_Failed)
  Socket_free (&server->listen_socket);
  SocketTLSContext_free (&server->tls_ctx);
  return -1;
  END_TRY;

  getsockname (
      Socket_fd (server->listen_socket), (struct sockaddr *)&addr, &len);

  server->port = ntohs (addr.sin_port);

  if (pthread_create (&server->thread, NULL, grpc_h2_server_thread, server) != 0)
    {
      Socket_free (&server->listen_socket);
      SocketTLSContext_free (&server->tls_ctx);
      return -1;
    }

  while (!server->started)
    usleep (1000);

  return 0;
}

static void
grpc_h2_server_stop (GRPC_H2_Server *server)
{
  if (server->listen_socket != NULL)
    Socket_free (&server->listen_socket);
  pthread_join (server->thread, NULL);
  if (server->tls_ctx != NULL)
    SocketTLSContext_free (&server->tls_ctx);
}

static int
metadata_contains_ascii (SocketGRPC_Metadata_T metadata,
                         const char *key,
                         const char *value)
{
  size_t i;

  if (metadata == NULL || key == NULL || value == NULL)
    return 0;
  for (i = 0; i < SocketGRPC_Metadata_count (metadata); i++)
    {
      const SocketGRPC_MetadataEntry *entry = SocketGRPC_Metadata_at (metadata, i);
      if (entry == NULL || entry->key == NULL || entry->is_binary != 0)
        continue;
      if (strcmp (entry->key, key) == 0 && entry->value_len == strlen (value)
          && memcmp (entry->value, value, entry->value_len) == 0)
        return 1;
    }
  return 0;
}

TEST (grpc_unary_h2_success_integration_roundtrip)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  Arena_T arena = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  uint8_t request_payload[] = { 0x08, 0x01 };
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int rc;
  char target[128];

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () != 0)
    {
      printf ("  [SKIP] Could not generate TLS cert fixtures\n");
      return;
    }
  if (grpc_h2_server_start (&server, GRPC_H2_SCENARIO_SUCCESS) != 0)
    {
      printf ("  [SKIP] Could not start gRPC/HTTP2 test server\n");
      cleanup_temp_cert_files ();
      return;
    }

  SocketTLSContext_T tls_client_ctx = SocketTLSContext_new_client (cert_path);
  ASSERT_NOT_NULL (tls_client_ctx);
  {
    const char *alpn[] = { "h2" };
    SocketTLSContext_set_alpn_protos (tls_client_ctx, alpn, 1);
  }

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.verify_peer = 1;
  channel_cfg.tls_context = tls_client_ctx;
  channel_cfg.max_metadata_entries = 8;

  client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);
  snprintf (target, sizeof (target), "https://127.0.0.1:%d", server.port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.EchoService/Ping", NULL);
  ASSERT_NOT_NULL (call);
  ASSERT_EQ (0, SocketGRPC_Call_metadata_add_ascii (call, "x-client-id", "abc"));

  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 sizeof (request_payload),
                                 arena,
                                 &response_payload,
                                 &response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_OK, rc);
  ASSERT_NOT_NULL (response_payload);
  ASSERT_EQ (2U, response_payload_len);
  ASSERT_EQ (0x08, response_payload[0]);
  ASSERT_EQ (0x2A, response_payload[1]);
  ASSERT_EQ (SOCKET_GRPC_STATUS_OK, SocketGRPC_Call_status (call).code);

  {
    SocketGRPC_Trailers_T trailers = SocketGRPC_Call_trailers (call);
    ASSERT_NOT_NULL (trailers);
    ASSERT (SocketGRPC_Trailers_has_status (trailers));
    ASSERT_EQ (SOCKET_GRPC_STATUS_OK, SocketGRPC_Trailers_status (trailers));
    ASSERT (metadata_contains_ascii (
        SocketGRPC_Trailers_metadata (trailers), "x-trace-id", "trace-123"));
  }

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();
}

TEST (grpc_unary_h2_http_status_fallback_on_non_grpc_body)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  Arena_T arena = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  uint8_t request_payload[] = { 0x08, 0x09 };
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int rc;
  char target[128];

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () != 0)
    {
      printf ("  [SKIP] Could not generate TLS cert fixtures\n");
      return;
    }
  if (grpc_h2_server_start (&server, GRPC_H2_SCENARIO_HTTP503_BAD_BODY) != 0)
    {
      printf ("  [SKIP] Could not start gRPC/HTTP2 test server\n");
      cleanup_temp_cert_files ();
      return;
    }

  SocketTLSContext_T tls_client_ctx = SocketTLSContext_new_client (cert_path);
  ASSERT_NOT_NULL (tls_client_ctx);
  {
    const char *alpn[] = { "h2" };
    SocketTLSContext_set_alpn_protos (tls_client_ctx, alpn, 1);
  }

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.verify_peer = 1;
  channel_cfg.tls_context = tls_client_ctx;

  client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);
  snprintf (target, sizeof (target), "https://127.0.0.1:%d", server.port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.EchoService/Ping", NULL);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 sizeof (request_payload),
                                 arena,
                                 &response_payload,
                                 &response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE, rc);
  ASSERT_NULL (response_payload);
  ASSERT_EQ (0U, response_payload_len);
  {
    SocketGRPC_Status status = SocketGRPC_Call_status (call);
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE, status.code);
    ASSERT_EQ (0,
               strcmp (
                   SocketGRPC_Status_message (&status), "Service unavailable"));
  }

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();
}

TEST (grpc_unary_h2_handles_trailers_only_error_response)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  Arena_T arena = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  uint8_t request_payload[] = { 0x08, 0x03 };
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int rc;
  char target[128];

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () != 0)
    {
      printf ("  [SKIP] Could not generate TLS cert fixtures\n");
      return;
    }
  if (grpc_h2_server_start (&server, GRPC_H2_SCENARIO_TRAILERS_ONLY_ERROR) != 0)
    {
      printf ("  [SKIP] Could not start gRPC/HTTP2 test server\n");
      cleanup_temp_cert_files ();
      return;
    }

  SocketTLSContext_T tls_client_ctx = SocketTLSContext_new_client (cert_path);
  ASSERT_NOT_NULL (tls_client_ctx);
  {
    const char *alpn[] = { "h2" };
    SocketTLSContext_set_alpn_protos (tls_client_ctx, alpn, 1);
  }

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.verify_peer = 1;
  channel_cfg.tls_context = tls_client_ctx;

  client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);
  snprintf (target, sizeof (target), "https://127.0.0.1:%d", server.port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.EchoService/Ping", NULL);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 sizeof (request_payload),
                                 arena,
                                 &response_payload,
                                 &response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE, rc);
  ASSERT_NULL (response_payload);
  ASSERT_EQ (0U, response_payload_len);

  {
    SocketGRPC_Status status = SocketGRPC_Call_status (call);
    SocketGRPC_Trailers_T trailers = SocketGRPC_Call_trailers (call);
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE, status.code);
    ASSERT_EQ (0,
               strcmp (SocketGRPC_Status_message (&status),
                       "upstream unavailable"));
    ASSERT_NOT_NULL (trailers);
    ASSERT (SocketGRPC_Trailers_has_status (trailers));
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE, SocketGRPC_Trailers_status (trailers));
    ASSERT_EQ (0,
               strcmp (SocketGRPC_Trailers_message (trailers),
                       "upstream unavailable"));
  }

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

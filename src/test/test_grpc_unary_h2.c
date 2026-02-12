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
#include <errno.h>
#include <limits.h>
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
#define GRPC_H2_MAX_OBSERVED_ATTEMPTS 8

typedef enum
{
  GRPC_H2_SCENARIO_SUCCESS = 0,
  GRPC_H2_SCENARIO_HTTP503_BAD_BODY = 1,
  GRPC_H2_SCENARIO_TRAILERS_ONLY_ERROR = 2,
  GRPC_H2_SCENARIO_STREAM_CLIENT_UPLOAD = 3,
  GRPC_H2_SCENARIO_STREAM_SERVER_STREAM = 4,
  GRPC_H2_SCENARIO_STREAM_BIDI_ERROR = 5,
  GRPC_H2_SCENARIO_DELAYED_SUCCESS_SHORT = 6,
  GRPC_H2_SCENARIO_DELAYED_SUCCESS_LONG = 7,
  GRPC_H2_SCENARIO_RETRY_UNAVAILABLE_THEN_SUCCESS = 8,
  GRPC_H2_SCENARIO_RETRY_ALWAYS_UNAVAILABLE = 9,
  GRPC_H2_SCENARIO_RETRY_NON_RETRYABLE = 10
} GRPC_H2_Scenario;

typedef struct
{
  Socket_T listen_socket;
  SocketTLSContext_T tls_ctx;
  pthread_t thread;
  volatile int started;
  int port;
  GRPC_H2_Scenario scenario;
  int max_connections;
  volatile int handled_connections;
  int observed_previous_attempt_count;
  int observed_previous_attempts[GRPC_H2_MAX_OBSERVED_ATTEMPTS];
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
tls_send_once_safe (Socket_T socket, const unsigned char *data, size_t len)
{
  volatile ssize_t n = -1;

  TRY
  {
    n = SocketTLS_send (socket, data, len);
  }
  EXCEPT (SocketTLS_Failed)
  {
    n = -1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    n = -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    n = -1;
  }
  EXCEPT (Socket_Failed)
  {
    n = -1;
  }
  EXCEPT (Socket_Closed)
  {
    n = -1;
  }
  ELSE
  {
    n = -1;
  }
  END_TRY;

  return (int)n;
}

static int
tls_recv_once_safe (Socket_T socket, unsigned char *buf, size_t len)
{
  volatile ssize_t n = -1;

  TRY
  {
    n = SocketTLS_recv (socket, buf, len);
  }
  EXCEPT (SocketTLS_Failed)
  {
    n = -1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    n = -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    n = -1;
  }
  EXCEPT (Socket_Failed)
  {
    n = -1;
  }
  EXCEPT (Socket_Closed)
  {
    n = -1;
  }
  ELSE
  {
    n = -1;
  }
  END_TRY;

  return (int)n;
}

static int
tls_send_all (Socket_T socket, const unsigned char *data, size_t len)
{
  size_t off = 0;
  while (off < len)
    {
      int n = tls_send_once_safe (socket, data + off, len - off);
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
      int n = tls_recv_once_safe (socket, buf + off, len - off);
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
buffer_append (unsigned char **buffer,
               size_t *buffer_len,
               size_t *buffer_cap,
               const unsigned char *chunk,
               size_t chunk_len)
{
  size_t needed;
  unsigned char *tmp;

  if (buffer == NULL || buffer_len == NULL || buffer_cap == NULL
      || (chunk == NULL && chunk_len != 0))
    return -1;
  if (chunk_len == 0)
    return 0;

  needed = *buffer_len + chunk_len;
  if (needed > *buffer_cap)
    {
      size_t new_cap = (*buffer_cap == 0) ? 1024U : *buffer_cap;
      while (new_cap < needed)
        new_cap *= 2U;
      tmp = (unsigned char *)realloc (*buffer, new_cap);
      if (tmp == NULL)
        return -1;
      *buffer = tmp;
      *buffer_cap = new_cap;
    }

  memcpy (*buffer + *buffer_len, chunk, chunk_len);
  *buffer_len += chunk_len;
  return 0;
}

static int
h2_extract_header_block_fragment (const unsigned char *payload,
                                  size_t payload_len,
                                  uint8_t flags,
                                  const unsigned char **fragment_out,
                                  size_t *fragment_len_out)
{
  size_t offset = 0;
  size_t len = payload_len;

  if (payload == NULL || fragment_out == NULL || fragment_len_out == NULL)
    return -1;

  if ((flags & HTTP2_FLAG_PADDED) != 0)
    {
      uint8_t pad_len;
      if (len < 1)
        return -1;
      pad_len = payload[0];
      offset += 1;
      len -= 1;
      if ((size_t)pad_len > len)
        return -1;
      len -= (size_t)pad_len;
    }

  if ((flags & HTTP2_FLAG_PRIORITY) != 0)
    {
      if (len < 5)
        return -1;
      offset += 5;
      len -= 5;
    }

  *fragment_out = payload + offset;
  *fragment_len_out = len;
  return 0;
}

static int
h2_decode_previous_attempts_header (const unsigned char *header_block,
                                    size_t header_block_len,
                                    int *previous_attempts_out)
{
  SocketHPACK_DecoderConfig cfg;
  SocketHPACK_Decoder_T decoder = NULL;
  SocketHPACK_Header headers[SOCKETHTTP2_MAX_DECODED_HEADERS];
  Arena_T arena = NULL;
  size_t header_count = 0;
  size_t i;

  if (header_block == NULL || previous_attempts_out == NULL)
    return -1;

  *previous_attempts_out = -1;

  arena = Arena_new ();
  if (arena == NULL)
    return -1;

  SocketHPACK_decoder_config_defaults (&cfg);
  decoder = SocketHPACK_Decoder_new (&cfg, arena);
  if (decoder == NULL)
    {
      Arena_dispose (&arena);
      return -1;
    }

  if (SocketHPACK_Decoder_decode (decoder,
                                  header_block,
                                  header_block_len,
                                  headers,
                                  SOCKETHTTP2_MAX_DECODED_HEADERS,
                                  &header_count,
                                  arena)
      != HPACK_OK)
    {
      SocketHPACK_Decoder_free (&decoder);
      Arena_dispose (&arena);
      return -1;
    }

  for (i = 0; i < header_count; i++)
    {
      const SocketHPACK_Header *h = &headers[i];
      if (h->name == NULL || h->value == NULL)
        continue;
      if (h->name_len == strlen ("grpc-previous-rpc-attempts")
          && memcmp (
                 h->name, "grpc-previous-rpc-attempts", h->name_len) == 0)
        {
          char value_buf[32];
          char *end = NULL;
          long parsed;

          if (h->value_len == 0 || h->value_len >= sizeof (value_buf))
            {
              SocketHPACK_Decoder_free (&decoder);
              Arena_dispose (&arena);
              return -1;
            }

          memcpy (value_buf, h->value, h->value_len);
          value_buf[h->value_len] = '\0';
          errno = 0;
          parsed = strtol (value_buf, &end, 10);
          if (errno != 0 || end == value_buf || end == NULL || *end != '\0'
              || parsed < 0 || parsed > INT_MAX)
            {
              SocketHPACK_Decoder_free (&decoder);
              Arena_dispose (&arena);
              return -1;
            }

          *previous_attempts_out = (int)parsed;
          break;
        }
    }

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);
  return 0;
}

static int
consume_client_request_payload (Socket_T client,
                                unsigned char **payload_out,
                                size_t *payload_len_out,
                                int *previous_attempts_out)
{
  unsigned char *payload_buffer = NULL;
  size_t payload_len = 0;
  size_t payload_cap = 0;
  int got_headers = 0;
  int end_stream = 0;
  int loops = 0;

  if (payload_out == NULL || payload_len_out == NULL)
    return -1;

  *payload_out = NULL;
  *payload_len_out = 0;
  if (previous_attempts_out != NULL)
    *previous_attempts_out = -1;

  while (loops++ < 256)
    {
      SocketHTTP2_FrameHeader fh;
      unsigned char *payload = NULL;

      if (recv_h2_frame (client, &fh, &payload) != 0)
        goto fail;

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
              goto fail;
            }
        }
      else if (fh.stream_id == 1U && fh.type == HTTP2_FRAME_HEADERS)
        {
          if (previous_attempts_out != NULL)
            {
              const unsigned char *header_fragment = NULL;
              size_t header_fragment_len = 0;

              if (h2_extract_header_block_fragment (payload,
                                                    fh.length,
                                                    fh.flags,
                                                    &header_fragment,
                                                    &header_fragment_len)
                  != 0)
                {
                  free (payload);
                  goto fail;
                }
              if (h2_decode_previous_attempts_header (
                      header_fragment, header_fragment_len, previous_attempts_out)
                  != 0)
                {
                  free (payload);
                  goto fail;
                }
            }
          got_headers = 1;
          if ((fh.flags & HTTP2_FLAG_END_STREAM) != 0)
            end_stream = 1;
        }
      else if (fh.stream_id == 1U && fh.type == HTTP2_FRAME_DATA)
        {
          if (buffer_append (
                  &payload_buffer, &payload_len, &payload_cap, payload, fh.length)
              != 0)
            {
              free (payload);
              goto fail;
            }
          if ((fh.flags & HTTP2_FLAG_END_STREAM) != 0)
            end_stream = 1;
        }

      free (payload);

      if (got_headers && end_stream)
        {
          *payload_out = payload_buffer;
          *payload_len_out = payload_len;
          return 0;
        }
    }

fail:
  free (payload_buffer);
  return -1;
}

static int
grpc_count_request_messages (const unsigned char *payload,
                             size_t payload_len,
                             size_t *count_out,
                             size_t *last_payload_len_out)
{
  size_t offset = 0;
  size_t count = 0;
  size_t last_payload_len = 0;

  if ((payload == NULL && payload_len != 0) || count_out == NULL
      || last_payload_len_out == NULL)
    return -1;

  while (offset < payload_len)
    {
      SocketGRPC_FrameView frame;
      size_t consumed = 0;
      SocketGRPC_WireResult rc = SocketGRPC_Frame_parse (
          payload + offset, payload_len - offset, (1024U * 1024U), &frame, &consumed);
      if (rc != SOCKET_GRPC_WIRE_OK || frame.compressed != 0 || consumed == 0)
        return -1;
      count++;
      last_payload_len = frame.payload_len;
      offset += consumed;
    }

  if (offset != payload_len)
    return -1;

  *count_out = count;
  *last_payload_len_out = last_payload_len;
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
consume_client_request (Socket_T client, int *previous_attempts_out)
{
  unsigned char *payload = NULL;
  size_t payload_len = 0;
  int rc = consume_client_request_payload (
      client, &payload, &payload_len, previous_attempts_out);
  free (payload);
  (void)payload_len;
  return rc;
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
send_trailers_only_status_response (Socket_T client,
                                    const char *grpc_status,
                                    const char *grpc_message)
{
  SocketHPACK_Header trailers_only_headers[4];
  unsigned char header_block[384];
  size_t header_count = 0;
  size_t header_block_len = 0;

  if (client == NULL || grpc_status == NULL)
    return -1;

  trailers_only_headers[header_count++]
      = (SocketHPACK_Header){ ":status", 7, "200", 3, 0 };
  trailers_only_headers[header_count++]
      = (SocketHPACK_Header){ "content-type", 12, "application/grpc", 16, 0 };
  trailers_only_headers[header_count++] = (SocketHPACK_Header){
    "grpc-status", 11, grpc_status, strlen (grpc_status), 0
  };
  if (grpc_message != NULL)
    {
      trailers_only_headers[header_count++] = (SocketHPACK_Header){
        "grpc-message", 12, grpc_message, strlen (grpc_message), 0
      };
    }

  if (encode_hpack_block (trailers_only_headers,
                          header_count,
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

static int
send_trailers_only_error_response (Socket_T client)
{
  return send_trailers_only_status_response (
      client, "14", "upstream unavailable");
}

static int
send_stream_initial_headers (Socket_T client)
{
  SocketHPACK_Header response_headers[] = {
    { ":status", 7, "200", 3, 0 },
    { "content-type", 12, "application/grpc", 16, 0 },
  };
  unsigned char header_block[256];
  size_t header_block_len = 0;

  if (encode_hpack_block (response_headers,
                          sizeof (response_headers) / sizeof (response_headers[0]),
                          header_block,
                          sizeof (header_block),
                          &header_block_len)
      != 0)
    return -1;

  return send_h2_frame (client,
                        HTTP2_FRAME_HEADERS,
                        HTTP2_FLAG_END_HEADERS,
                        1,
                        header_block,
                        header_block_len);
}

static int
send_stream_data_message (Socket_T client,
                          const uint8_t *payload,
                          size_t payload_len)
{
  unsigned char framed[128];
  size_t framed_len = 0;

  if (SocketGRPC_Frame_encode (0,
                               payload,
                               (uint32_t)payload_len,
                               framed,
                               sizeof (framed),
                               &framed_len)
      != SOCKET_GRPC_WIRE_OK)
    return -1;

  return send_h2_frame (client, HTTP2_FRAME_DATA, 0, 1, framed, framed_len);
}

static int
send_stream_status_trailers (Socket_T client, const char *status, const char *message)
{
  SocketHPACK_Header trailers[2];
  unsigned char header_block[256];
  size_t trailer_count = 0;
  size_t header_block_len = 0;

  trailers[trailer_count++] = (SocketHPACK_Header){ "grpc-status", 11,
                                                    status, strlen (status), 0 };
  if (message != NULL)
    {
      trailers[trailer_count++]
          = (SocketHPACK_Header){ "grpc-message", 12, message, strlen (message), 0 };
    }

  if (encode_hpack_block (
          trailers, trailer_count, header_block, sizeof (header_block), &header_block_len)
      != 0)
    return -1;

  return send_h2_frame (client,
                        HTTP2_FRAME_HEADERS,
                        HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
                        1,
                        header_block,
                        header_block_len);
}

static int
send_stream_client_upload_response (Socket_T client,
                                    size_t request_messages,
                                    size_t last_payload_len)
{
  uint8_t ack_payload[] = { 0x08,
                            (uint8_t)(request_messages & 0x7F),
                            0x10,
                            (uint8_t)(last_payload_len & 0x7F) };

  if (send_stream_initial_headers (client) != 0)
    return -1;
  if (send_stream_data_message (
          client, ack_payload, sizeof (ack_payload))
      != 0)
    return -1;
  return send_stream_status_trailers (client, "0", NULL);
}

static int
send_stream_server_stream_response (Socket_T client)
{
  static const uint8_t msg1[] = { 0x08, 0x01 };
  static const uint8_t msg2[] = { 0x08, 0x02 };
  static const uint8_t msg3[] = { 0x08, 0x03 };

  if (send_stream_initial_headers (client) != 0)
    return -1;
  if (send_stream_data_message (client, msg1, sizeof (msg1)) != 0)
    return -1;
  if (send_stream_data_message (client, msg2, sizeof (msg2)) != 0)
    return -1;
  if (send_stream_data_message (client, msg3, sizeof (msg3)) != 0)
    return -1;
  return send_stream_status_trailers (client, "0", NULL);
}

static int
send_stream_bidi_error_response (Socket_T client)
{
  static const uint8_t msg[] = { 0x08, 0x2A };

  if (send_stream_initial_headers (client) != 0)
    return -1;
  if (send_stream_data_message (client, msg, sizeof (msg)) != 0)
    return -1;
  return send_stream_status_trailers (client, "14", "stream aborted");
}

static int
grpc_h2_scenario_is_unary (GRPC_H2_Scenario scenario)
{
  return scenario == GRPC_H2_SCENARIO_SUCCESS
         || scenario == GRPC_H2_SCENARIO_HTTP503_BAD_BODY
         || scenario == GRPC_H2_SCENARIO_TRAILERS_ONLY_ERROR
         || scenario == GRPC_H2_SCENARIO_DELAYED_SUCCESS_SHORT
         || scenario == GRPC_H2_SCENARIO_DELAYED_SUCCESS_LONG
         || scenario == GRPC_H2_SCENARIO_RETRY_UNAVAILABLE_THEN_SUCCESS
         || scenario == GRPC_H2_SCENARIO_RETRY_ALWAYS_UNAVAILABLE
         || scenario == GRPC_H2_SCENARIO_RETRY_NON_RETRYABLE;
}

static int
grpc_h2_server_handle_client (GRPC_H2_Server *server,
                              Socket_T client,
                              int connection_index)
{
  unsigned char preface[H2_CLIENT_PREFACE_LEN];
  TLSHandshakeState hs_state;
  int hs_loops = 0;

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
    return -1;

  {
    const char *alpn = SocketTLS_get_alpn_selected (client);
    if (alpn == NULL || strcmp (alpn, "h2") != 0)
      return -1;
  }

  if (tls_recv_exact (client, preface, sizeof (preface)) != 0
      || memcmp (preface, H2_CLIENT_PREFACE, sizeof (preface)) != 0)
    {
      return -1;
    }

  if (send_h2_frame (client, HTTP2_FRAME_SETTINGS, 0, 0, NULL, 0) != 0)
    return -1;

  if (grpc_h2_scenario_is_unary (server->scenario))
    {
      int previous_attempts = -1;
      if (consume_client_request (client, &previous_attempts) != 0)
        return -1;

      if (connection_index >= 0
          && connection_index < GRPC_H2_MAX_OBSERVED_ATTEMPTS)
        {
          server->observed_previous_attempts[connection_index]
              = previous_attempts;
          if (server->observed_previous_attempt_count < (connection_index + 1))
            server->observed_previous_attempt_count = connection_index + 1;
        }

      if (server->scenario == GRPC_H2_SCENARIO_SUCCESS)
        return send_success_response (client);
      if (server->scenario == GRPC_H2_SCENARIO_DELAYED_SUCCESS_SHORT)
        {
          usleep (20000);
          return send_success_response (client);
        }
      if (server->scenario == GRPC_H2_SCENARIO_DELAYED_SUCCESS_LONG)
        {
          usleep (200000);
          return send_success_response (client);
        }
      if (server->scenario == GRPC_H2_SCENARIO_HTTP503_BAD_BODY)
        return send_http503_bad_body_response (client);
      if (server->scenario == GRPC_H2_SCENARIO_TRAILERS_ONLY_ERROR)
        return send_trailers_only_error_response (client);
      if (server->scenario == GRPC_H2_SCENARIO_RETRY_UNAVAILABLE_THEN_SUCCESS)
        {
          if (connection_index == 0)
            {
              return send_trailers_only_status_response (
                  client, "14", "upstream unavailable");
            }
          return send_success_response (client);
        }
      if (server->scenario == GRPC_H2_SCENARIO_RETRY_ALWAYS_UNAVAILABLE)
        {
          return send_trailers_only_status_response (
              client, "14", "upstream unavailable");
        }

      return send_trailers_only_status_response (
          client, "3", "invalid request");
    }
  else
    {
      unsigned char *request_payload = NULL;
      size_t request_payload_len = 0;
      size_t request_messages = 0;
      size_t last_message_len = 0;
      int rc = 0;

      if (consume_client_request_payload (
              client, &request_payload, &request_payload_len, NULL)
          != 0)
        {
          free (request_payload);
          return -1;
        }

      if (request_payload_len > 0
          && grpc_count_request_messages (request_payload,
                                          request_payload_len,
                                          &request_messages,
                                          &last_message_len)
                 != 0)
        {
          free (request_payload);
          return -1;
        }

      if (server->scenario == GRPC_H2_SCENARIO_STREAM_CLIENT_UPLOAD)
        {
          rc = send_stream_client_upload_response (
              client, request_messages, last_message_len);
        }
      else if (server->scenario == GRPC_H2_SCENARIO_STREAM_SERVER_STREAM)
        {
          rc = send_stream_server_stream_response (client);
        }
      else
        {
          rc = send_stream_bidi_error_response (client);
        }

      free (request_payload);
      return rc;
    }
}

static void *
grpc_h2_server_thread (void *arg)
{
  GRPC_H2_Server *server = (GRPC_H2_Server *)arg;
  int startup_idle_polls = 0;
  int post_accept_idle_polls = 0;

  server->started = 1;

  while (server->max_connections <= 0
         || server->handled_connections < server->max_connections)
    {
      Socket_T client = Socket_accept_timeout (server->listen_socket, 50);
      if (client == NULL)
        {
          if (server->handled_connections > 0)
            {
              if (++post_accept_idle_polls >= 4)
                break;
            }
          else
            {
              if (++startup_idle_polls >= 100)
                break;
            }
          continue;
        }

      if (grpc_h2_server_handle_client (server, client, server->handled_connections)
          != 0)
        {
          Socket_free (&client);
          break;
        }

      startup_idle_polls = 0;
      post_accept_idle_polls = 0;
      server->handled_connections++;
      usleep (20000);
      Socket_free (&client);
    }

  return NULL;
}

static int
grpc_h2_server_start_with_limit (GRPC_H2_Server *server,
                                 GRPC_H2_Scenario scenario,
                                 int max_connections)
{
  struct sockaddr_in addr;
  socklen_t len = sizeof (addr);
  const char *alpn_protos[] = { "h2", "http/1.1" };
  int i;

  memset (server, 0, sizeof (*server));
  server->scenario = scenario;
  server->max_connections = max_connections;
  if (server->max_connections <= 0)
    server->max_connections = 1;
  for (i = 0; i < GRPC_H2_MAX_OBSERVED_ATTEMPTS; i++)
    server->observed_previous_attempts[i] = -1;

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

static int
grpc_h2_server_start (GRPC_H2_Server *server, GRPC_H2_Scenario scenario)
{
  return grpc_h2_server_start_with_limit (server, scenario, 1);
}

static void
grpc_h2_server_stop (GRPC_H2_Server *server)
{
  pthread_join (server->thread, NULL);
  if (server->listen_socket != NULL)
    Socket_free (&server->listen_socket);
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

TEST (grpc_unary_h2_deadline_exceeded_maps_consistently)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  Arena_T arena = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_CallConfig call_cfg;
  uint8_t request_payload[] = { 0x08, 0x07 };
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
  if (grpc_h2_server_start (&server, GRPC_H2_SCENARIO_DELAYED_SUCCESS_LONG) != 0)
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
  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = 30;

  client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);
  snprintf (target, sizeof (target), "https://127.0.0.1:%d", server.port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.EchoService/Ping", &call_cfg);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 sizeof (request_payload),
                                 arena,
                                 &response_payload,
                                 &response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED, rc);
  ASSERT_NULL (response_payload);
  ASSERT_EQ (0U, response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
             SocketGRPC_Call_status (call).code);

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();
}

TEST (grpc_unary_h2_response_before_deadline_remains_ok)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  Arena_T arena = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_CallConfig call_cfg;
  uint8_t request_payload[] = { 0x08, 0x08 };
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
  if (grpc_h2_server_start (&server, GRPC_H2_SCENARIO_DELAYED_SUCCESS_SHORT) != 0)
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
  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = 200;

  client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);
  snprintf (target, sizeof (target), "https://127.0.0.1:%d", server.port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.EchoService/Ping", &call_cfg);
  ASSERT_NOT_NULL (call);
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
  ASSERT_EQ (SOCKET_GRPC_STATUS_OK, SocketGRPC_Call_status (call).code);

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();
}

TEST (grpc_unary_h2_retry_unavailable_then_success)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ClientConfig client_cfg;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_CallConfig call_cfg;
  Arena_T arena = NULL;
  SocketTLSContext_T tls_client_ctx = NULL;
  uint8_t request_payload[] = { 0x08, 0x11 };
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
  if (grpc_h2_server_start_with_limit (
          &server, GRPC_H2_SCENARIO_RETRY_UNAVAILABLE_THEN_SUCCESS, 3)
      != 0)
    {
      printf ("  [SKIP] Could not start gRPC/HTTP2 retry test server\n");
      cleanup_temp_cert_files ();
      return;
    }

  tls_client_ctx = SocketTLSContext_new_client (cert_path);
  ASSERT_NOT_NULL (tls_client_ctx);
  {
    const char *alpn[] = { "h2" };
    SocketTLSContext_set_alpn_protos (tls_client_ctx, alpn, 1);
  }

  SocketGRPC_ClientConfig_defaults (&client_cfg);
  client_cfg.enable_retry = 1;
  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.verify_peer = 1;
  channel_cfg.tls_context = tls_client_ctx;
  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = 1000;
  call_cfg.retry_policy.max_attempts = 3;
  call_cfg.retry_policy.initial_backoff_ms = 5;
  call_cfg.retry_policy.max_backoff_ms = 20;
  call_cfg.retry_policy.backoff_multiplier = 1.0;
  call_cfg.retry_policy.jitter_percent = 0;
  call_cfg.retry_policy.retryable_status_mask
      = (1U << SOCKET_GRPC_STATUS_UNAVAILABLE);

  client = SocketGRPC_Client_new (&client_cfg);
  ASSERT_NOT_NULL (client);
  snprintf (target, sizeof (target), "https://127.0.0.1:%d", server.port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.EchoService/Ping", &call_cfg);
  ASSERT_NOT_NULL (call);
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
  ASSERT_EQ (SOCKET_GRPC_STATUS_OK, SocketGRPC_Call_status (call).code);

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();

  ASSERT_EQ (2, server.handled_connections);
  ASSERT_EQ (-1, server.observed_previous_attempts[0]);
  ASSERT_EQ (1, server.observed_previous_attempts[1]);
}

TEST (grpc_unary_h2_retry_deadline_exceeded_before_all_attempts)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ClientConfig client_cfg;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_CallConfig call_cfg;
  Arena_T arena = NULL;
  SocketTLSContext_T tls_client_ctx = NULL;
  uint8_t request_payload[] = { 0x08, 0x12 };
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
  if (grpc_h2_server_start_with_limit (
          &server, GRPC_H2_SCENARIO_RETRY_ALWAYS_UNAVAILABLE, 4)
      != 0)
    {
      printf ("  [SKIP] Could not start gRPC/HTTP2 retry test server\n");
      cleanup_temp_cert_files ();
      return;
    }

  tls_client_ctx = SocketTLSContext_new_client (cert_path);
  ASSERT_NOT_NULL (tls_client_ctx);
  {
    const char *alpn[] = { "h2" };
    SocketTLSContext_set_alpn_protos (tls_client_ctx, alpn, 1);
  }

  SocketGRPC_ClientConfig_defaults (&client_cfg);
  client_cfg.enable_retry = 1;
  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.verify_peer = 1;
  channel_cfg.tls_context = tls_client_ctx;
  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = 35;
  call_cfg.retry_policy.max_attempts = 4;
  call_cfg.retry_policy.initial_backoff_ms = 80;
  call_cfg.retry_policy.max_backoff_ms = 80;
  call_cfg.retry_policy.backoff_multiplier = 1.0;
  call_cfg.retry_policy.jitter_percent = 0;
  call_cfg.retry_policy.retryable_status_mask
      = (1U << SOCKET_GRPC_STATUS_UNAVAILABLE);

  client = SocketGRPC_Client_new (&client_cfg);
  ASSERT_NOT_NULL (client);
  snprintf (target, sizeof (target), "https://127.0.0.1:%d", server.port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.EchoService/Ping", &call_cfg);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 sizeof (request_payload),
                                 arena,
                                 &response_payload,
                                 &response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED, rc);
  ASSERT_NULL (response_payload);
  ASSERT_EQ (0U, response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
             SocketGRPC_Call_status (call).code);
  ASSERT_EQ (SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
             SocketGRPC_Trailers_status (SocketGRPC_Call_trailers (call)));

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();

  ASSERT_EQ (1, server.handled_connections);
}

TEST (grpc_unary_h2_retry_ignores_non_retryable_status)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ClientConfig client_cfg;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_CallConfig call_cfg;
  Arena_T arena = NULL;
  SocketTLSContext_T tls_client_ctx = NULL;
  uint8_t request_payload[] = { 0x08, 0x13 };
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
  if (grpc_h2_server_start_with_limit (
          &server, GRPC_H2_SCENARIO_RETRY_NON_RETRYABLE, 3)
      != 0)
    {
      printf ("  [SKIP] Could not start gRPC/HTTP2 retry test server\n");
      cleanup_temp_cert_files ();
      return;
    }

  tls_client_ctx = SocketTLSContext_new_client (cert_path);
  ASSERT_NOT_NULL (tls_client_ctx);
  {
    const char *alpn[] = { "h2" };
    SocketTLSContext_set_alpn_protos (tls_client_ctx, alpn, 1);
  }

  SocketGRPC_ClientConfig_defaults (&client_cfg);
  client_cfg.enable_retry = 1;
  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.verify_peer = 1;
  channel_cfg.tls_context = tls_client_ctx;
  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = 1000;
  call_cfg.retry_policy.max_attempts = 4;
  call_cfg.retry_policy.initial_backoff_ms = 5;
  call_cfg.retry_policy.max_backoff_ms = 20;
  call_cfg.retry_policy.backoff_multiplier = 1.0;
  call_cfg.retry_policy.jitter_percent = 0;
  call_cfg.retry_policy.retryable_status_mask
      = (1U << SOCKET_GRPC_STATUS_UNAVAILABLE);

  client = SocketGRPC_Client_new (&client_cfg);
  ASSERT_NOT_NULL (client);
  snprintf (target, sizeof (target), "https://127.0.0.1:%d", server.port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.EchoService/Ping", &call_cfg);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 sizeof (request_payload),
                                 arena,
                                 &response_payload,
                                 &response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_INVALID_ARGUMENT, rc);
  ASSERT_NULL (response_payload);
  ASSERT_EQ (0U, response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_INVALID_ARGUMENT,
             SocketGRPC_Call_status (call).code);

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();

  ASSERT_EQ (1, server.handled_connections);
  ASSERT_EQ (-1, server.observed_previous_attempts[0]);
}

TEST (grpc_stream_h2_client_upload_roundtrip)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  Arena_T arena = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketTLSContext_T tls_client_ctx = NULL;
  uint8_t small1[] = { 0x08, 0x01 };
  uint8_t small2[] = { 0x08, 0x02 };
  uint8_t *large_payload = NULL;
  const size_t large_payload_len = 40000U;
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int done = 0;
  char target[128];

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () != 0)
    {
      printf ("  [SKIP] Could not generate TLS cert fixtures\n");
      return;
    }
  if (grpc_h2_server_start (&server, GRPC_H2_SCENARIO_STREAM_CLIENT_UPLOAD) != 0)
    {
      printf ("  [SKIP] Could not start gRPC/HTTP2 test server\n");
      cleanup_temp_cert_files ();
      return;
    }

  tls_client_ctx = SocketTLSContext_new_client (cert_path);
  ASSERT_NOT_NULL (tls_client_ctx);
  {
    const char *alpn[] = { "h2" };
    SocketTLSContext_set_alpn_protos (tls_client_ctx, alpn, 1);
  }

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.verify_peer = 1;
  channel_cfg.tls_context = tls_client_ctx;
  channel_cfg.max_outbound_message_bytes = 128U * 1024U;
  channel_cfg.max_inbound_message_bytes = 128U * 1024U;

  client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);
  snprintf (target, sizeof (target), "https://127.0.0.1:%d", server.port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.Streamer/Upload", NULL);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  large_payload = (uint8_t *)malloc (large_payload_len);
  ASSERT_NOT_NULL (large_payload);
  memset (large_payload, 0xAB, large_payload_len);

  ASSERT_EQ (0, SocketGRPC_Call_send_message (call, small1, sizeof (small1)));
  ASSERT_EQ (0, SocketGRPC_Call_send_message (call, small2, sizeof (small2)));
  ASSERT_EQ (
      0, SocketGRPC_Call_send_message (call, large_payload, large_payload_len));
  ASSERT_EQ (0, SocketGRPC_Call_close_send (call));

  ASSERT_EQ (0,
             SocketGRPC_Call_recv_message (
                 call, arena, &response_payload, &response_payload_len, &done));
  ASSERT_EQ (0, done);
  ASSERT_NOT_NULL (response_payload);
  ASSERT_EQ (4U, response_payload_len);
  ASSERT_EQ (0x08, response_payload[0]);
  ASSERT_EQ (3, response_payload[1]);
  ASSERT_EQ (0x10, response_payload[2]);
  ASSERT_EQ ((int)(large_payload_len & 0x7FU), response_payload[3]);

  response_payload = NULL;
  response_payload_len = 0;
  ASSERT_EQ (0,
             SocketGRPC_Call_recv_message (
                 call, arena, &response_payload, &response_payload_len, &done));
  ASSERT_EQ (1, done);
  ASSERT_NULL (response_payload);
  ASSERT_EQ (0U, response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_OK, SocketGRPC_Call_status (call).code);
  ASSERT_EQ (SOCKET_GRPC_STATUS_OK,
             SocketGRPC_Trailers_status (SocketGRPC_Call_trailers (call)));

  free (large_payload);
  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();
}

TEST (grpc_stream_h2_server_streaming_messages)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  Arena_T arena = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketTLSContext_T tls_client_ctx = NULL;
  uint8_t request_payload[] = { 0x08, 0x01 };
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int done = 0;
  char target[128];

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () != 0)
    {
      printf ("  [SKIP] Could not generate TLS cert fixtures\n");
      return;
    }
  if (grpc_h2_server_start (&server, GRPC_H2_SCENARIO_STREAM_SERVER_STREAM) != 0)
    {
      printf ("  [SKIP] Could not start gRPC/HTTP2 test server\n");
      cleanup_temp_cert_files ();
      return;
    }

  tls_client_ctx = SocketTLSContext_new_client (cert_path);
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
  call = SocketGRPC_Call_new (channel, "/test.Streamer/Subscribe", NULL);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  ASSERT_EQ (
      0, SocketGRPC_Call_send_message (call, request_payload, sizeof (request_payload)));
  ASSERT_EQ (0, SocketGRPC_Call_close_send (call));
  ASSERT_EQ (-1, SocketGRPC_Call_send_message (call, request_payload, 1));

  ASSERT_EQ (0,
             SocketGRPC_Call_recv_message (
                 call, arena, &response_payload, &response_payload_len, &done));
  ASSERT_EQ (0, done);
  ASSERT_EQ (2U, response_payload_len);
  ASSERT_EQ (0x01, response_payload[1]);

  ASSERT_EQ (0,
             SocketGRPC_Call_recv_message (
                 call, arena, &response_payload, &response_payload_len, &done));
  ASSERT_EQ (0, done);
  ASSERT_EQ (2U, response_payload_len);
  ASSERT_EQ (0x02, response_payload[1]);

  ASSERT_EQ (0,
             SocketGRPC_Call_recv_message (
                 call, arena, &response_payload, &response_payload_len, &done));
  ASSERT_EQ (0, done);
  ASSERT_EQ (2U, response_payload_len);
  ASSERT_EQ (0x03, response_payload[1]);

  response_payload = NULL;
  response_payload_len = 0;
  ASSERT_EQ (0,
             SocketGRPC_Call_recv_message (
                 call, arena, &response_payload, &response_payload_len, &done));
  ASSERT_EQ (1, done);
  ASSERT_EQ (SOCKET_GRPC_STATUS_OK, SocketGRPC_Call_status (call).code);

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();
}

TEST (grpc_stream_h2_midstream_error_maps_to_trailers_status)
{
  GRPC_H2_Server server;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  Arena_T arena = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketTLSContext_T tls_client_ctx = NULL;
  uint8_t request_payload[] = { 0x08, 0x05 };
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int done = 0;
  char target[128];

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () != 0)
    {
      printf ("  [SKIP] Could not generate TLS cert fixtures\n");
      return;
    }
  if (grpc_h2_server_start (&server, GRPC_H2_SCENARIO_STREAM_BIDI_ERROR) != 0)
    {
      printf ("  [SKIP] Could not start gRPC/HTTP2 test server\n");
      cleanup_temp_cert_files ();
      return;
    }

  tls_client_ctx = SocketTLSContext_new_client (cert_path);
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
  call = SocketGRPC_Call_new (channel, "/test.Streamer/Chat", NULL);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  ASSERT_EQ (
      0, SocketGRPC_Call_send_message (call, request_payload, sizeof (request_payload)));
  ASSERT_EQ (0, SocketGRPC_Call_close_send (call));

  ASSERT_EQ (0,
             SocketGRPC_Call_recv_message (
                 call, arena, &response_payload, &response_payload_len, &done));
  ASSERT_EQ (0, done);
  ASSERT_EQ (2U, response_payload_len);
  ASSERT_EQ (0x2A, response_payload[1]);

  response_payload = NULL;
  response_payload_len = 0;
  ASSERT_EQ (0,
             SocketGRPC_Call_recv_message (
                 call, arena, &response_payload, &response_payload_len, &done));
  ASSERT_EQ (1, done);
  {
    SocketGRPC_Status status = SocketGRPC_Call_status (call);
    ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE, status.code);
    ASSERT_EQ (0, strcmp (SocketGRPC_Status_message (&status), "stream aborted"));
  }
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE,
             SocketGRPC_Trailers_status (SocketGRPC_Call_trailers (call)));

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&tls_client_ctx);
  grpc_h2_server_stop (&server);
  cleanup_temp_cert_files ();
}

TEST (grpc_stream_h2_client_cancel_sets_terminal_status)
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
  int done = 0;
  char target[128];

  signal (SIGPIPE, SIG_IGN);

  if (create_temp_cert_files () != 0)
    {
      printf ("  [SKIP] Could not generate TLS cert fixtures\n");
      return;
    }
  if (grpc_h2_server_start (&server, GRPC_H2_SCENARIO_STREAM_SERVER_STREAM) != 0)
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
  call = SocketGRPC_Call_new (channel, "/test.Streamer/Subscribe", NULL);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  ASSERT_EQ (
      0, SocketGRPC_Call_send_message (call, request_payload, sizeof (request_payload)));
  ASSERT_EQ (0, SocketGRPC_Call_cancel (call));
  ASSERT_EQ (SOCKET_GRPC_STATUS_CANCELLED, SocketGRPC_Call_status (call).code);
  ASSERT_EQ (-1,
             SocketGRPC_Call_recv_message (
                 call, arena, &response_payload, &response_payload_len, &done));

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

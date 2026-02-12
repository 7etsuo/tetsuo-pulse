/*
 * SPDX-License-Identifier: MIT
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "grpc/SocketGRPC.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  int smoke;
  int use_h3;
  int insecure;
  const char *target;
  const char *method;
} ChatOptions;

typedef struct
{
  int send_events;
  int recv_events;
} ChatProbe;

static void
usage (const char *prog)
{
  printf ("Usage: %s [options]\n", prog);
  printf ("\n");
  printf ("Options:\n");
  printf ("  --smoke             Run deterministic CI smoke path\n");
  printf ("  --target <url>      gRPC target (example: https://127.0.0.1:50051)\n");
  printf ("  --method <path>     Full method path (default: /example.Chat/Chat)\n");
  printf ("  --h3                Use HTTP/3 channel mode\n");
  printf ("  --insecure          Disable peer verification\n");
  printf ("  -h, --help          Show this help\n");
}

static int
parse_args (int argc, char **argv, ChatOptions *opts)
{
  int i;

  if (opts == NULL)
    return -1;

  opts->smoke = 0;
  opts->use_h3 = 0;
  opts->insecure = 0;
  opts->target = NULL;
  opts->method = "/example.Chat/Chat";

  for (i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "--smoke") == 0)
        {
          opts->smoke = 1;
        }
      else if (strcmp (argv[i], "--h3") == 0)
        {
          opts->use_h3 = 1;
        }
      else if (strcmp (argv[i], "--insecure") == 0)
        {
          opts->insecure = 1;
        }
      else if ((strcmp (argv[i], "--target") == 0) && (i + 1 < argc))
        {
          opts->target = argv[++i];
        }
      else if ((strcmp (argv[i], "--method") == 0) && (i + 1 < argc))
        {
          opts->method = argv[++i];
        }
      else if ((strcmp (argv[i], "-h") == 0) || (strcmp (argv[i], "--help") == 0))
        {
          usage (argv[0]);
          return 1;
        }
      else
        {
          fprintf (stderr, "Unknown argument: %s\n", argv[i]);
          usage (argv[0]);
          return -1;
        }
    }

  return 0;
}

static int
chat_probe_interceptor (SocketGRPC_Call_T call,
                        SocketGRPC_StreamInterceptEvent event,
                        const uint8_t *payload,
                        size_t payload_len,
                        SocketGRPC_Status *status_io,
                        void *userdata)
{
  ChatProbe *probe = (ChatProbe *)userdata;
  (void)call;
  (void)payload;
  (void)payload_len;
  (void)status_io;

  if (probe == NULL)
    return SOCKET_GRPC_INTERCEPT_CONTINUE;
  if (event == SOCKET_GRPC_STREAM_INTERCEPT_SEND)
    probe->send_events++;
  else if (event == SOCKET_GRPC_STREAM_INTERCEPT_RECV)
    probe->recv_events++;
  return SOCKET_GRPC_INTERCEPT_CONTINUE;
}

static int
run_smoke (void)
{
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  ChatProbe probe;
  int rc = 1;

  memset (&probe, 0, sizeof (probe));

  client = SocketGRPC_Client_new (NULL);
  if (client == NULL)
    goto cleanup;

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel = SocketGRPC_Channel_new (client, "dns:///grpc-chat-smoke.local", &channel_cfg);
  if (channel == NULL)
    goto cleanup;

  call = SocketGRPC_Call_new (channel, "/example.Chat/Chat", NULL);
  if (call == NULL)
    goto cleanup;

  if (SocketGRPC_Call_add_stream_interceptor (call,
                                              chat_probe_interceptor,
                                              &probe)
      != 0)
    goto cleanup;

  if (SocketGRPC_Call_metadata_add_ascii (call, "x-chat-room", "smoke") != 0)
    goto cleanup;

  if (SocketGRPC_Call_cancel (call) != 0)
    goto cleanup;

  printf ("grpc bidi chat smoke: PASS\n");
  rc = 0;

cleanup:
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  return rc;
}

static int
run_live (const ChatOptions *opts)
{
  Arena_T arena = NULL;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  uint8_t *payload = NULL;
  size_t payload_len = 0;
  int done = 0;
  int rc;
  int exit_code = 1;
  const uint8_t msg1[] = { 0x0A, 0x05, 'h', 'e', 'l', 'l', 'o' };
  const uint8_t msg2[] = { 0x0A, 0x05, 'w', 'o', 'r', 'l', 'd' };

  if (opts == NULL || opts->target == NULL)
    {
      fprintf (stderr, "--target is required when not using --smoke\n");
      return 1;
    }

  arena = Arena_new ();
  if (arena == NULL)
    return 1;

  client = SocketGRPC_Client_new (NULL);
  if (client == NULL)
    goto cleanup;

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.channel_mode = opts->use_h3 ? SOCKET_GRPC_CHANNEL_MODE_HTTP3
                                          : SOCKET_GRPC_CHANNEL_MODE_HTTP2;
  channel_cfg.verify_peer = opts->insecure ? 0 : 1;

  channel = SocketGRPC_Channel_new (client, opts->target, &channel_cfg);
  if (channel == NULL)
    goto cleanup;

  call = SocketGRPC_Call_new (channel, opts->method, NULL);
  if (call == NULL)
    goto cleanup;

  rc = SocketGRPC_Call_send_message (call, msg1, sizeof (msg1));
  if (rc != 0)
    goto report;

  rc = SocketGRPC_Call_send_message (call, msg2, sizeof (msg2));
  if (rc != 0)
    goto report;

  rc = SocketGRPC_Call_close_send (call);
  if (rc != 0)
    goto report;

  while (!done)
    {
      rc = SocketGRPC_Call_recv_message (
          call, arena, &payload, &payload_len, &done);
      if (rc != 0)
        goto report;
      if (!done)
        printf ("recv payload bytes=%zu\n", payload_len);
    }

report:
  {
    SocketGRPC_Status status = SocketGRPC_Call_status (call);
    printf ("transport=%s rc=%d status=%d message=%s\n",
            opts->use_h3 ? "h3" : "h2",
            rc,
            (int)status.code,
            SocketGRPC_Status_message (&status));
    if (rc == 0 && status.code == SOCKET_GRPC_STATUS_OK)
      exit_code = 0;
  }

cleanup:
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  Arena_dispose (&arena);
  return exit_code;
}

int
main (int argc, char **argv)
{
  ChatOptions opts;
  int parse_rc;

  parse_rc = parse_args (argc, argv, &opts);
  if (parse_rc > 0)
    return 0;
  if (parse_rc < 0)
    return 2;

  if (opts.smoke)
    return run_smoke ();
  return run_live (&opts);
}

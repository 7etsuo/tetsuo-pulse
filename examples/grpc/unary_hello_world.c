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
  const char *message;
} UnaryOptions;

static void
usage (const char *prog)
{
  printf ("Usage: %s [options]\n", prog);
  printf ("\n");
  printf ("Options:\n");
  printf ("  --smoke             Run deterministic CI smoke path\n");
  printf ("  --target <url>      gRPC target (example: https://127.0.0.1:50051)\n");
  printf ("  --method <path>     Full method path (default: /example.Echo/Ping)\n");
  printf ("  --message <text>    Request payload bytes (default: hello from tetsuo)\n");
  printf ("  --h3                Use HTTP/3 channel mode\n");
  printf ("  --insecure          Disable peer verification\n");
  printf ("  -h, --help          Show this help\n");
}

static int
parse_args (int argc, char **argv, UnaryOptions *opts)
{
  int i;

  if (opts == NULL)
    return -1;

  opts->smoke = 0;
  opts->use_h3 = 0;
  opts->insecure = 0;
  opts->target = NULL;
  opts->method = "/example.Echo/Ping";
  opts->message = "hello from tetsuo";

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
      else if ((strcmp (argv[i], "--message") == 0) && (i + 1 < argc))
        {
          opts->message = argv[++i];
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
run_smoke (void)
{
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_Status status;
  int rc = 1;

  client = SocketGRPC_Client_new (NULL);
  if (client == NULL)
    goto cleanup;

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel = SocketGRPC_Channel_new (client, "dns:///grpc-smoke.local", &channel_cfg);
  if (channel == NULL)
    goto cleanup;

  call = SocketGRPC_Call_new (channel, "/example.Echo/Ping", NULL);
  if (call == NULL)
    goto cleanup;

  if (SocketGRPC_Call_metadata_add_ascii (call, "x-example-mode", "smoke") != 0)
    goto cleanup;

  if (SocketGRPC_Call_cancel (call) != 0)
    goto cleanup;

  status = SocketGRPC_Call_status (call);
  if (status.code != SOCKET_GRPC_STATUS_CANCELLED)
    goto cleanup;

  printf ("grpc unary hello-world smoke: PASS\n");
  rc = 0;

cleanup:
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  return rc;
}

static int
run_live (const UnaryOptions *opts)
{
  Arena_T arena = NULL;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  const uint8_t *request_payload = NULL;
  size_t request_payload_len = 0;
  SocketGRPC_Status status;
  volatile int rc = -1;
  volatile int exit_code = 1;

  if (opts == NULL || opts->target == NULL)
    {
      fprintf (stderr, "--target is required when not using --smoke\n");
      return 1;
    }

  request_payload = (const uint8_t *)opts->message;
  request_payload_len = strlen (opts->message);

  arena = Arena_new ();
  if (arena == NULL)
    {
      fprintf (stderr, "failed to allocate arena\n");
      return 1;
    }

  client = SocketGRPC_Client_new (NULL);
  if (client == NULL)
    {
      fprintf (stderr, "failed to allocate grpc client\n");
      goto cleanup;
    }

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.channel_mode = opts->use_h3 ? SOCKET_GRPC_CHANNEL_MODE_HTTP3
                                          : SOCKET_GRPC_CHANNEL_MODE_HTTP2;
  channel_cfg.verify_peer = opts->insecure ? 0 : 1;

  channel = SocketGRPC_Channel_new (client, opts->target, &channel_cfg);
  if (channel == NULL)
    {
      fprintf (stderr, "failed to create channel\n");
      goto cleanup;
    }

  call = SocketGRPC_Call_new (channel, opts->method, NULL);
  if (call == NULL)
    {
      fprintf (stderr, "failed to create call\n");
      goto cleanup;
    }

  TRY
    {
      rc = SocketGRPC_Call_unary_h2 (call,
                                     request_payload,
                                     request_payload_len,
                                     arena,
                                     &response_payload,
                                     &response_payload_len);
    }
  ELSE
    {
      rc = -1;
    }
  END_TRY;

  status = SocketGRPC_Call_status (call);

  printf ("transport=%s rc=%d status=%d message=%s\n",
          opts->use_h3 ? "h3" : "h2",
          (int)rc,
          (int)status.code,
          SocketGRPC_Status_message (&status));

  if (rc == SOCKET_GRPC_STATUS_OK)
    {
      printf ("response-bytes=%zu\n", response_payload_len);
      if (response_payload != NULL && response_payload_len > 0)
        {
          printf ("response-text=%.*s\n",
                  (int)response_payload_len,
                  (const char *)response_payload);
        }
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
  UnaryOptions opts;
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

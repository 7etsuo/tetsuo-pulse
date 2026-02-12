/*
 * SPDX-License-Identifier: MIT
 */

#include "core/Arena.h"
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
  int cancel_before_send;
  int deadline_ms;
  const char *target;
  const char *method;
} DeadlineOptions;

static void
usage (const char *prog)
{
  printf ("Usage: %s [options]\n", prog);
  printf ("\n");
  printf ("Options:\n");
  printf ("  --smoke                Run deterministic CI smoke path\n");
  printf ("  --target <url>         gRPC target (example: https://127.0.0.1:50051)\n");
  printf ("  --method <path>        Full method path (default: /example.Echo/Ping)\n");
  printf ("  --deadline-ms <ms>     Deadline in milliseconds (default: 100)\n");
  printf ("  --cancel-before-send   Cancel call before invoking unary\n");
  printf ("  --h3                   Use HTTP/3 channel mode\n");
  printf ("  --insecure             Disable peer verification\n");
  printf ("  -h, --help             Show this help\n");
}

static int
parse_deadline_ms (const char *value, int *out)
{
  char *end = NULL;
  long parsed;

  if (value == NULL || out == NULL)
    return -1;

  parsed = strtol (value, &end, 10);
  if (end == value || end == NULL || *end != '\0')
    return -1;
  if (parsed <= 0 || parsed > 600000)
    return -1;

  *out = (int)parsed;
  return 0;
}

static int
parse_args (int argc, char **argv, DeadlineOptions *opts)
{
  int i;

  if (opts == NULL)
    return -1;

  opts->smoke = 0;
  opts->use_h3 = 0;
  opts->insecure = 0;
  opts->cancel_before_send = 0;
  opts->deadline_ms = 100;
  opts->target = NULL;
  opts->method = "/example.Echo/Ping";

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
      else if (strcmp (argv[i], "--cancel-before-send") == 0)
        {
          opts->cancel_before_send = 1;
        }
      else if ((strcmp (argv[i], "--target") == 0) && (i + 1 < argc))
        {
          opts->target = argv[++i];
        }
      else if ((strcmp (argv[i], "--method") == 0) && (i + 1 < argc))
        {
          opts->method = argv[++i];
        }
      else if ((strcmp (argv[i], "--deadline-ms") == 0) && (i + 1 < argc))
        {
          if (parse_deadline_ms (argv[++i], &opts->deadline_ms) != 0)
            {
              fprintf (stderr, "Invalid deadline value\n");
              return -1;
            }
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
  char timeout_value[32];
  int64_t parsed_ms = 0;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_CallConfig call_cfg;
  int rc = 1;

  if (SocketGRPC_Timeout_format (250, timeout_value, sizeof (timeout_value)) != 0)
    goto cleanup;
  if (SocketGRPC_Timeout_parse (timeout_value, &parsed_ms) != 0 || parsed_ms != 250)
    goto cleanup;

  client = SocketGRPC_Client_new (NULL);
  if (client == NULL)
    goto cleanup;

  channel
      = SocketGRPC_Channel_new (client, "dns:///grpc-deadline-smoke.local", NULL);
  if (channel == NULL)
    goto cleanup;

  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = 25;
  call = SocketGRPC_Call_new (channel, "/example.Echo/Ping", &call_cfg);
  if (call == NULL)
    goto cleanup;

  if (SocketGRPC_Call_cancel (call) != 0)
    goto cleanup;

  if (SocketGRPC_Call_status (call).code != SOCKET_GRPC_STATUS_CANCELLED)
    goto cleanup;

  printf ("grpc deadline/cancellation smoke: PASS\n");
  rc = 0;

cleanup:
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  return rc;
}

static int
run_live (const DeadlineOptions *opts)
{
  Arena_T arena = NULL;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_CallConfig call_cfg;
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  const uint8_t request_payload[] = { 0x0A, 0x04, 'p', 'i', 'n', 'g' };
  int rc = -1;
  int exit_code = 1;

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

  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = opts->deadline_ms;
  call = SocketGRPC_Call_new (channel, opts->method, &call_cfg);
  if (call == NULL)
    goto cleanup;

  if (opts->cancel_before_send)
    {
      if (SocketGRPC_Call_cancel (call) != 0)
        goto report;
    }

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 sizeof (request_payload),
                                 arena,
                                 &response_payload,
                                 &response_payload_len);

report:
  {
    SocketGRPC_Status status = SocketGRPC_Call_status (call);
    printf ("transport=%s deadline_ms=%d rc=%d status=%d message=%s\n",
            opts->use_h3 ? "h3" : "h2",
            opts->deadline_ms,
            rc,
            (int)status.code,
            SocketGRPC_Status_message (&status));
    if (rc == SOCKET_GRPC_STATUS_OK
        || status.code == SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED
        || status.code == SOCKET_GRPC_STATUS_CANCELLED)
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
  DeadlineOptions opts;
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

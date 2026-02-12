/*
 * SPDX-License-Identifier: MIT
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "grpc/SocketGRPC.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  int smoke;
  int insecure;
  const char *target;
  const char *method;
  const char *ca_file;
  const char *client_cert;
  const char *client_key;
  const char *message;
} TLSOptions;

static void
usage (const char *prog)
{
  printf ("Usage: %s [options]\n", prog);
  printf ("\n");
  printf ("Options:\n");
  printf ("  --smoke                Run deterministic CI smoke path\n");
  printf ("  --target <url>         gRPC target (example: https://127.0.0.1:50051)\n");
  printf ("  --method <path>        Full method path (default: /example.Echo/Ping)\n");
  printf ("  --ca <path>            CA bundle for server verification\n");
  printf ("  --client-cert <path>   Client certificate (PEM) for mTLS\n");
  printf ("  --client-key <path>    Client key (PEM) for mTLS\n");
  printf ("  --message <text>       Request payload (default: tls-demo)\n");
  printf ("  --insecure             Disable peer verification\n");
  printf ("  -h, --help             Show this help\n");
}

static int
parse_args (int argc, char **argv, TLSOptions *opts)
{
  int i;

  if (opts == NULL)
    return -1;

  opts->smoke = 0;
  opts->insecure = 0;
  opts->target = NULL;
  opts->method = "/example.Echo/Ping";
  opts->ca_file = NULL;
  opts->client_cert = NULL;
  opts->client_key = NULL;
  opts->message = "tls-demo";

  for (i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "--smoke") == 0)
        {
          opts->smoke = 1;
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
      else if ((strcmp (argv[i], "--ca") == 0) && (i + 1 < argc))
        {
          opts->ca_file = argv[++i];
        }
      else if ((strcmp (argv[i], "--client-cert") == 0) && (i + 1 < argc))
        {
          opts->client_cert = argv[++i];
        }
      else if ((strcmp (argv[i], "--client-key") == 0) && (i + 1 < argc))
        {
          opts->client_key = argv[++i];
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

#if SOCKET_HAS_TLS

static SocketTLSContext_T
build_client_tls (const TLSOptions *opts)
{
  SocketTLSContext_T ctx = NULL;

  if (opts == NULL)
    return NULL;

  TRY
    {
      ctx = SocketTLSContext_new_client (opts->ca_file);
    }
  EXCEPT (SocketTLS_Failed)
    {
      return NULL;
    }
  END_TRY;

  if (ctx == NULL)
    return NULL;

  if (opts->client_cert != NULL || opts->client_key != NULL)
    {
      if (opts->client_cert == NULL || opts->client_key == NULL)
        {
          SocketTLSContext_free (&ctx);
          return NULL;
        }

      TRY
        {
          SocketTLSContext_load_certificate (
              ctx, opts->client_cert, opts->client_key);
        }
      EXCEPT (SocketTLS_Failed)
        {
          SocketTLSContext_free (&ctx);
          return NULL;
        }
      END_TRY;
    }

  return ctx;
}

static int
run_smoke (void)
{
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketTLSContext_T client_tls = NULL;
  int rc = 1;

  TLSOptions opts;
  memset (&opts, 0, sizeof (opts));

  client_tls = build_client_tls (&opts);
  if (client_tls == NULL)
    goto cleanup;

  client = SocketGRPC_Client_new (NULL);
  if (client == NULL)
    goto cleanup;

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.channel_mode = SOCKET_GRPC_CHANNEL_MODE_HTTP2;
  channel_cfg.tls_context = client_tls;
  channel_cfg.verify_peer = 0;

  channel = SocketGRPC_Channel_new (client, "https://127.0.0.1:443", &channel_cfg);
  if (channel == NULL)
    goto cleanup;

  call = SocketGRPC_Call_new (channel, "/example.Echo/Ping", NULL);
  if (call == NULL)
    goto cleanup;

  if (SocketGRPC_Call_cancel (call) != 0)
    goto cleanup;

  printf ("grpc tls/mtls h2 smoke: PASS\n");
  rc = 0;

cleanup:
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&client_tls);
  return rc;
}

static int
run_live (const TLSOptions *opts)
{
  Arena_T arena = NULL;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketTLSContext_T client_tls = NULL;
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  const uint8_t *request_payload = NULL;
  size_t request_payload_len = 0;
  int rc = -1;
  int exit_code = 1;

  if (opts == NULL || opts->target == NULL)
    {
      fprintf (stderr, "--target is required when not using --smoke\n");
      return 1;
    }

  if (!opts->insecure && opts->ca_file == NULL)
    {
      fprintf (stderr, "--ca is required unless --insecure is used\n");
      return 1;
    }

  if ((opts->client_cert != NULL && opts->client_key == NULL)
      || (opts->client_cert == NULL && opts->client_key != NULL))
    {
      fprintf (stderr, "--client-cert and --client-key must be provided together\n");
      return 1;
    }

  arena = Arena_new ();
  if (arena == NULL)
    return 1;

  client_tls = build_client_tls (opts);
  if (client_tls == NULL)
    {
      fprintf (stderr, "failed to create client TLS context\n");
      goto cleanup;
    }

  if (opts->insecure)
    {
      TRY
        {
          SocketTLSContext_set_verify_mode (client_tls, TLS_VERIFY_NONE);
        }
      EXCEPT (SocketTLS_Failed)
        {
          fprintf (stderr, "failed to set insecure verify mode\n");
          goto cleanup;
        }
      END_TRY;
    }

  client = SocketGRPC_Client_new (NULL);
  if (client == NULL)
    goto cleanup;

  request_payload = (const uint8_t *)opts->message;
  request_payload_len = strlen (opts->message);

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.channel_mode = SOCKET_GRPC_CHANNEL_MODE_HTTP2;
  channel_cfg.tls_context = client_tls;
  channel_cfg.verify_peer = opts->insecure ? 0 : 1;

  channel = SocketGRPC_Channel_new (client, opts->target, &channel_cfg);
  if (channel == NULL)
    goto cleanup;

  call = SocketGRPC_Call_new (channel, opts->method, NULL);
  if (call == NULL)
    goto cleanup;

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 request_payload_len,
                                 arena,
                                 &response_payload,
                                 &response_payload_len);

  {
    SocketGRPC_Status status = SocketGRPC_Call_status (call);
    printf ("transport=h2 tls_context=enabled rc=%d status=%d message=%s\n",
            rc,
            (int)status.code,
            SocketGRPC_Status_message (&status));
    if (opts->client_cert != NULL)
      printf ("mTLS client cert mode enabled\n");
    if (rc == SOCKET_GRPC_STATUS_OK)
      exit_code = 0;
  }

cleanup:
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&client_tls);
  Arena_dispose (&arena);
  return exit_code;
}

#else

static int
run_smoke (void)
{
  printf ("grpc tls/mtls h2 smoke: SKIPPED (SOCKET_HAS_TLS=0)\n");
  return 0;
}

static int
run_live (const TLSOptions *opts)
{
  (void)opts;
  fprintf (stderr, "TLS support is disabled in this build\n");
  return 1;
}

#endif

int
main (int argc, char **argv)
{
  TLSOptions opts;
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

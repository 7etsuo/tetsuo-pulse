/*
 * SPDX-License-Identifier: MIT
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "grpc/SocketGRPC.h"

#if SOCKET_HAS_TLS
#include "http/SocketHTTP3-server.h"
#include "http/SocketHTTPServer.h"
#include "tls/SocketTLSContext.h"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define BENCH_DEFAULT_ITERATIONS 200
#define BENCH_DEFAULT_WARMUP 20
#define BENCH_SMOKE_ITERATIONS 20
#define BENCH_SMOKE_WARMUP 3
#define BENCH_MAX_SCENARIOS 16
#define BENCH_STATUS_LEN 16
#define BENCH_NOTE_LEN 160
#define BENCH_CERT_PATH_CAP 256
#define BENCH_TARGET_CAP 160
#define BENCH_METHOD "/bench.Echo/Ping"
#define BENCH_H2_PORT_BASE 55100
#define BENCH_H3_PORT_BASE 56100
#define BENCH_SERVER_POLL_MS 20

typedef struct
{
  int iterations;
  int warmup;
  int smoke;
  const char *report_path;
} BenchConfig;

typedef struct
{
  const char *id;
  SocketGRPC_ChannelMode mode;
  size_t payload_bytes;
  int request_compression;
} BenchScenario;

typedef struct
{
  BenchScenario spec;
  char status[BENCH_STATUS_LEN];
  char note[BENCH_NOTE_LEN];
  int iterations;
  int warmup;
  int successes;
  double avg_ms;
  double p50_ms;
  double p95_ms;
  double p99_ms;
  double throughput_rps;
} BenchResult;

#if SOCKET_HAS_TLS
typedef struct
{
  SocketHTTPServer_T http2_server;
  SocketHTTP3_Server_T http3_server;
  SocketGRPC_Server_T grpc_server;
  SocketTLSContext_T server_tls;
  Arena_T arena;
  pthread_t thread;
  volatile int running;
  volatile int started;
  int use_h3;
  int port;
  char cert_path[BENCH_CERT_PATH_CAP];
  char key_path[BENCH_CERT_PATH_CAP];
} BenchFixture;
#endif

static int
parse_positive_int (const char *value, int min_value, int max_value, int *out)
{
  char *end = NULL;
  long parsed;

  if (value == NULL || out == NULL)
    return -1;

  errno = 0;
  parsed = strtol (value, &end, 10);
  if (errno != 0 || end == value || end == NULL || *end != '\0')
    return -1;
  if (parsed < min_value || parsed > max_value)
    return -1;

  *out = (int)parsed;
  return 0;
}

static void
usage (const char *prog)
{
  printf ("Usage: %s [options]\n", prog);
  printf ("\n");
  printf ("Options:\n");
  printf ("  --iterations <n>   Measured calls per scenario (default: %d)\n",
          BENCH_DEFAULT_ITERATIONS);
  printf ("  --warmup <n>       Warmup calls per scenario (default: %d)\n",
          BENCH_DEFAULT_WARMUP);
  printf ("  --smoke            CI smoke profile (%d iterations)\n",
          BENCH_SMOKE_ITERATIONS);
  printf ("  --report <path>    Write JSON report to file (default: stdout)\n");
  printf ("  -h, --help         Show this help\n");
}

static int
parse_args (int argc, char **argv, BenchConfig *cfg)
{
  int i;

  if (cfg == NULL)
    return -1;

  cfg->iterations = BENCH_DEFAULT_ITERATIONS;
  cfg->warmup = BENCH_DEFAULT_WARMUP;
  cfg->smoke = 0;
  cfg->report_path = NULL;

  for (i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "--smoke") == 0)
        {
          cfg->smoke = 1;
          cfg->iterations = BENCH_SMOKE_ITERATIONS;
          cfg->warmup = BENCH_SMOKE_WARMUP;
        }
      else if ((strcmp (argv[i], "--iterations") == 0) && (i + 1 < argc))
        {
          if (parse_positive_int (argv[++i], 1, 100000, &cfg->iterations) != 0)
            {
              fprintf (stderr, "Invalid --iterations value\n");
              return -1;
            }
        }
      else if ((strcmp (argv[i], "--warmup") == 0) && (i + 1 < argc))
        {
          if (parse_positive_int (argv[++i], 0, 100000, &cfg->warmup) != 0)
            {
              fprintf (stderr, "Invalid --warmup value\n");
              return -1;
            }
        }
      else if ((strcmp (argv[i], "--report") == 0) && (i + 1 < argc))
        {
          cfg->report_path = argv[++i];
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

static int64_t
now_ns (void)
{
  struct timespec ts;

  if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
    return 0;
  return ((int64_t)ts.tv_sec * 1000000000LL) + ts.tv_nsec;
}

static int
double_compare (const void *a, const void *b)
{
  double da = *(const double *)a;
  double db = *(const double *)b;
  if (da < db)
    return -1;
  if (da > db)
    return 1;
  return 0;
}

static double
percentile (double *values, size_t count, double pct)
{
  double pos;
  size_t idx;

  if (values == NULL || count == 0)
    return 0.0;
  if (pct <= 0.0)
    return values[0];
  if (pct >= 100.0)
    return values[count - 1U];

  pos = (pct / 100.0) * (double)(count - 1U);
  idx = (size_t)pos;
  return values[idx];
}

static void
json_print_string (FILE *out, const char *value)
{
  const unsigned char *p;

  if (out == NULL)
    return;

  fputc ('"', out);
  if (value != NULL)
    {
      for (p = (const unsigned char *)value; *p != '\0'; p++)
        {
          if (*p == '\\' || *p == '"')
            {
              fputc ('\\', out);
              fputc ((int)*p, out);
            }
          else if (*p == '\n')
            {
              fputs ("\\n", out);
            }
          else if (*p < 0x20)
            {
              fputc (' ', out);
            }
          else
            {
              fputc ((int)*p, out);
            }
        }
    }
  fputc ('"', out);
}

static void
iso8601_now_utc (char *out, size_t out_cap)
{
  time_t now;
  struct tm tm_utc;

  if (out == NULL || out_cap == 0)
    return;

  now = time (NULL);
  gmtime_r (&now, &tm_utc);
  strftime (out, out_cap, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

#if SOCKET_HAS_TLS

static int
next_h2_port (void)
{
  static int counter = 0;
  int port = BENCH_H2_PORT_BASE + (counter % 800);
  counter++;
  return port;
}

static int
next_h3_port (void)
{
  static int counter = 0;
  int port = BENCH_H3_PORT_BASE + (counter % 800);
  counter++;
  return port;
}

static int
create_temp_cert_files (char *cert_path,
                        size_t cert_cap,
                        char *key_path,
                        size_t key_cap)
{
  static int serial = 0;
  char cmd[1024];

  if (cert_path == NULL || key_path == NULL)
    return -1;

  snprintf (cert_path,
            cert_cap,
            "/tmp/grpc_bench_cert_%d_%d.pem",
            (int)getpid (),
            serial);
  snprintf (key_path,
            key_cap,
            "/tmp/grpc_bench_key_%d_%d.pem",
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
remove_temp_cert_files (BenchFixture *fixture)
{
  if (fixture == NULL)
    return;
  if (fixture->cert_path[0] != '\0')
    unlink (fixture->cert_path);
  if (fixture->key_path[0] != '\0')
    unlink (fixture->key_path);
  fixture->cert_path[0] = '\0';
  fixture->key_path[0] = '\0';
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

static void *
fixture_h2_thread_main (void *arg)
{
  BenchFixture *fixture = (BenchFixture *)arg;

  if (fixture == NULL || fixture->http2_server == NULL)
    return NULL;

  fixture->started = 1;
  while (fixture->running)
    SocketHTTPServer_process (fixture->http2_server, BENCH_SERVER_POLL_MS);

  return NULL;
}

static void *
fixture_h3_thread_main (void *arg)
{
  BenchFixture *fixture = (BenchFixture *)arg;

  if (fixture == NULL || fixture->http3_server == NULL)
    return NULL;

  if (SocketHTTP3_Server_start (fixture->http3_server) != 0)
    {
      fixture->started = -1;
      fixture->running = 0;
      return NULL;
    }

  fixture->started = 1;
  while (fixture->running)
    SocketHTTP3_Server_poll (fixture->http3_server, BENCH_SERVER_POLL_MS);

  return NULL;
}

static void
fixture_stop (BenchFixture *fixture)
{
  if (fixture == NULL)
    return;

  if (fixture->grpc_server != NULL)
    SocketGRPC_Server_begin_shutdown (fixture->grpc_server);

  if (fixture->running)
    {
      fixture->running = 0;
      if (!fixture->use_h3)
        {
          if (fixture->http2_server != NULL)
            SocketHTTPServer_stop (fixture->http2_server);
        }
      pthread_join (fixture->thread, NULL);
    }

  SocketHTTPServer_free (&fixture->http2_server);
  if (fixture->http3_server != NULL)
    {
      SocketHTTP3_Server_close (fixture->http3_server);
      fixture->http3_server = NULL;
    }
  SocketGRPC_Server_free (&fixture->grpc_server);
  SocketTLSContext_free (&fixture->server_tls);
  Arena_dispose (&fixture->arena);
  remove_temp_cert_files (fixture);
}

static int
fixture_start_h2 (BenchFixture *fixture)
{
  SocketHTTPServer_Config cfg;
  volatile int retries;
  volatile int started = 0;

  if (fixture == NULL)
    return -1;

  memset (fixture, 0, sizeof (*fixture));

  if (create_temp_cert_files (fixture->cert_path,
                              sizeof (fixture->cert_path),
                              fixture->key_path,
                              sizeof (fixture->key_path))
      != 0)
    {
      return -1;
    }

  TRY
    {
      const char *alpn[2] = { "h2", "http/1.1" };
      fixture->server_tls
          = SocketTLSContext_new_server (fixture->cert_path, fixture->key_path, NULL);
      SocketTLSContext_set_alpn_protos (fixture->server_tls, alpn, 2);
    }
  EXCEPT (SocketTLS_Failed)
    {
      fixture_stop (fixture);
      return -1;
    }
  END_TRY;

  fixture->grpc_server = SocketGRPC_Server_new (NULL);
  if (fixture->grpc_server == NULL)
    {
      fixture_stop (fixture);
      return -1;
    }

  if (SocketGRPC_Server_register_unary (
          fixture->grpc_server, BENCH_METHOD, grpc_echo_handler, NULL)
      != 0)
    {
      fixture_stop (fixture);
      return -1;
    }

  for (retries = 0; retries < 10 && !started; retries++)
    {
      fixture->port = next_h2_port ();
      SocketHTTPServer_config_defaults (&cfg);
      cfg.bind_address = "127.0.0.1";
      cfg.port = fixture->port;
      cfg.max_version = HTTP_VERSION_2;
      cfg.tls_context = fixture->server_tls;

      TRY
        {
          fixture->http2_server = SocketHTTPServer_new (&cfg);
          if (fixture->http2_server != NULL)
            {
              SocketGRPC_Server_bind_http2 (fixture->grpc_server,
                                            fixture->http2_server);
              if (SocketHTTPServer_start (fixture->http2_server) == 0)
                started = 1;
              else
                SocketHTTPServer_free (&fixture->http2_server);
            }
        }
      EXCEPT (SocketHTTPServer_Failed)
        {
          SocketHTTPServer_free (&fixture->http2_server);
        }
      EXCEPT (Socket_Failed)
        {
          SocketHTTPServer_free (&fixture->http2_server);
        }
      END_TRY;

      if (!started)
        usleep (10000);
    }

  if (!started)
    {
      fixture_stop (fixture);
      return -1;
    }

  fixture->use_h3 = 0;
  fixture->running = 1;
  if (pthread_create (&fixture->thread, NULL, fixture_h2_thread_main, fixture)
      != 0)
    {
      fixture_stop (fixture);
      return -1;
    }

  while (!fixture->started)
    usleep (1000);
  usleep (30000);
  return 0;
}

static int
fixture_start_h3 (BenchFixture *fixture)
{
  SocketHTTP3_ServerConfig cfg;

  if (fixture == NULL)
    return -1;

  memset (fixture, 0, sizeof (*fixture));

  if (create_temp_cert_files (fixture->cert_path,
                              sizeof (fixture->cert_path),
                              fixture->key_path,
                              sizeof (fixture->key_path))
      != 0)
    {
      return -1;
    }

  fixture->arena = Arena_new ();
  if (fixture->arena == NULL)
    {
      fixture_stop (fixture);
      return -1;
    }

  fixture->grpc_server = SocketGRPC_Server_new (NULL);
  if (fixture->grpc_server == NULL)
    {
      fixture_stop (fixture);
      return -1;
    }

  if (SocketGRPC_Server_register_unary (
          fixture->grpc_server, BENCH_METHOD, grpc_echo_handler, NULL)
      != 0)
    {
      fixture_stop (fixture);
      return -1;
    }

  SocketHTTP3_ServerConfig_defaults (&cfg);
  cfg.bind_addr = "127.0.0.1";
  cfg.port = next_h3_port ();
  cfg.cert_file = fixture->cert_path;
  cfg.key_file = fixture->key_path;

  fixture->port = cfg.port;
  fixture->http3_server = SocketHTTP3_Server_new (fixture->arena, &cfg);
  if (fixture->http3_server == NULL)
    {
      fixture_stop (fixture);
      return -1;
    }

  SocketGRPC_Server_bind_http3 (fixture->grpc_server, fixture->http3_server);

  fixture->use_h3 = 1;
  fixture->running = 1;
  fixture->started = 0;

  if (pthread_create (&fixture->thread, NULL, fixture_h3_thread_main, fixture)
      != 0)
    {
      fixture_stop (fixture);
      return -1;
    }

  while (fixture->running && fixture->started == 0)
    usleep (1000);

  if (fixture->started < 0)
    {
      fixture_stop (fixture);
      return -1;
    }

  usleep (30000);
  return 0;
}

static int
run_single_unary (const BenchScenario *scenario,
                  const BenchFixture *fixture,
                  const uint8_t *request_payload,
                  size_t request_payload_len,
                  double *latency_ms_out,
                  SocketGRPC_Status *status_out)
{
  Arena_T arena = NULL;
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_CallConfig call_cfg;
  SocketTLSContext_T client_tls = NULL;
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  char target[BENCH_TARGET_CAP];
  int64_t started_ns = 0;
  int64_t ended_ns = 0;
  volatile int rc = -1;
  SocketGRPC_Status status = { SOCKET_GRPC_STATUS_INTERNAL,
                               "call not started" };

  if (scenario == NULL || fixture == NULL || request_payload == NULL
      || request_payload_len == 0)
    {
      return -1;
    }

  if (status_out != NULL)
    {
      status_out->code = SOCKET_GRPC_STATUS_INTERNAL;
      status_out->message = "invalid arguments";
    }
  if (latency_ms_out != NULL)
    *latency_ms_out = 0.0;

  arena = Arena_new ();
  if (arena == NULL)
    goto cleanup;

  client = SocketGRPC_Client_new (NULL);
  if (client == NULL)
    goto cleanup;

  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  channel_cfg.channel_mode = scenario->mode;
  channel_cfg.verify_peer = 1;
  channel_cfg.enable_request_compression = scenario->request_compression;
  channel_cfg.enable_response_decompression = 1;

  if (scenario->mode == SOCKET_GRPC_CHANNEL_MODE_HTTP2)
    {
      TRY
        {
          client_tls = SocketTLSContext_new_client (fixture->cert_path);
        }
      EXCEPT (SocketTLS_Failed)
        {
          goto cleanup;
        }
      END_TRY;
      channel_cfg.tls_context = client_tls;
    }
  else
    {
      channel_cfg.ca_file = fixture->cert_path;
    }

  snprintf (target, sizeof (target), "https://127.0.0.1:%d", fixture->port);
  channel = SocketGRPC_Channel_new (client, target, &channel_cfg);
  if (channel == NULL)
    goto cleanup;

  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = 2000;
  call = SocketGRPC_Call_new (channel, BENCH_METHOD, &call_cfg);
  if (call == NULL)
    goto cleanup;

  started_ns = now_ns ();
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
  ended_ns = now_ns ();

  status = SocketGRPC_Call_status (call);

  if (latency_ms_out != NULL && started_ns > 0 && ended_ns >= started_ns)
    {
      *latency_ms_out = (double)(ended_ns - started_ns) / 1000000.0;
    }

  if (rc == SOCKET_GRPC_STATUS_OK)
    {
      if (response_payload == NULL || response_payload_len != request_payload_len)
        {
          status.code = SOCKET_GRPC_STATUS_INTERNAL;
          status.message = "response payload mismatch";
          rc = SOCKET_GRPC_STATUS_INTERNAL;
        }
      else if (memcmp (response_payload, request_payload, request_payload_len) != 0)
        {
          status.code = SOCKET_GRPC_STATUS_INTERNAL;
          status.message = "response payload differs";
          rc = SOCKET_GRPC_STATUS_INTERNAL;
        }
    }

cleanup:
  if (status_out != NULL)
    *status_out = status;

  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  SocketTLSContext_free (&client_tls);
  Arena_dispose (&arena);

  return (int)rc;
}

static void
set_result_status (BenchResult *result, const char *status, const char *note)
{
  if (result == NULL)
    return;

  if (status == NULL)
    status = "error";
  if (note == NULL)
    note = "";

  snprintf (result->status, sizeof (result->status), "%s", status);
  snprintf (result->note, sizeof (result->note), "%s", note);
}

static void
run_scenario (const BenchScenario *scenario,
              const BenchConfig *cfg,
              BenchResult *result)
{
  BenchFixture fixture;
  uint8_t *payload = NULL;
  double *latencies = NULL;
  int i;
  double sum_ms = 0.0;
  int started = 0;

  if (scenario == NULL || cfg == NULL || result == NULL)
    return;

  memset (&fixture, 0, sizeof (fixture));
  memset (result, 0, sizeof (*result));
  result->spec = *scenario;
  result->iterations = cfg->iterations;
  result->warmup = cfg->warmup;
  set_result_status (result, "error", "not executed");

  if (scenario->mode == SOCKET_GRPC_CHANNEL_MODE_HTTP3
      && scenario->request_compression)
    {
      set_result_status (result,
                         "unsupported",
                         "request compression over HTTP/3 is unsupported");
      return;
    }

  if (cfg->smoke && scenario->mode == SOCKET_GRPC_CHANNEL_MODE_HTTP2
      && scenario->request_compression)
    {
      set_result_status (
          result, "skipped", "smoke profile skips HTTP/2 compression stress case");
      return;
    }

  payload = (uint8_t *)malloc (scenario->payload_bytes);
  if (payload == NULL)
    {
      set_result_status (result, "error", "failed to allocate payload");
      return;
    }

  for (i = 0; i < (int)scenario->payload_bytes; i++)
    payload[i] = (uint8_t)(i & 0xff);

  if (scenario->mode == SOCKET_GRPC_CHANNEL_MODE_HTTP2)
    started = (fixture_start_h2 (&fixture) == 0);
  else
    started = (fixture_start_h3 (&fixture) == 0);

  if (!started)
    {
      if (scenario->mode == SOCKET_GRPC_CHANNEL_MODE_HTTP3)
        set_result_status (
            result, "skipped", "HTTP/3 runtime unavailable in this environment");
      else
        set_result_status (result, "error", "failed to start HTTP/2 fixture");
      goto cleanup;
    }

  for (i = 0; i < cfg->warmup; i++)
    {
      SocketGRPC_Status warm_status;
      double warm_latency_ms = 0.0;
      int warm_rc = run_single_unary (scenario,
                                      &fixture,
                                      payload,
                                      scenario->payload_bytes,
                                      &warm_latency_ms,
                                      &warm_status);
      if (warm_rc != SOCKET_GRPC_STATUS_OK)
        {
          if (scenario->mode == SOCKET_GRPC_CHANNEL_MODE_HTTP3
              && warm_status.code == SOCKET_GRPC_STATUS_UNAVAILABLE)
            {
              set_result_status (
                  result,
                  "skipped",
                  "HTTP/3 transport unavailable during warmup");
            }
          else if (scenario->mode == SOCKET_GRPC_CHANNEL_MODE_HTTP2
                   && scenario->request_compression)
            {
              set_result_status (
                  result,
                  "skipped",
                  "HTTP/2 request compression unavailable in this runtime");
            }
          else
            {
              set_result_status (result,
                                 "error",
                                 SocketGRPC_Status_message (&warm_status));
            }
          goto cleanup;
        }
    }

  latencies = (double *)malloc (sizeof (double) * (size_t)cfg->iterations);
  if (latencies == NULL)
    {
      set_result_status (result, "error", "failed to allocate latency array");
      goto cleanup;
    }

  for (i = 0; i < cfg->iterations; i++)
    {
      SocketGRPC_Status status;
      double latency_ms = 0.0;
      int rc = run_single_unary (scenario,
                                 &fixture,
                                 payload,
                                 scenario->payload_bytes,
                                 &latency_ms,
                                 &status);

      if (rc != SOCKET_GRPC_STATUS_OK)
        {
          if (scenario->mode == SOCKET_GRPC_CHANNEL_MODE_HTTP3
              && status.code == SOCKET_GRPC_STATUS_UNAVAILABLE)
            {
              set_result_status (
                  result,
                  "skipped",
                  "HTTP/3 transport unavailable during measured run");
            }
          else if (scenario->mode == SOCKET_GRPC_CHANNEL_MODE_HTTP2
                   && scenario->request_compression)
            {
              set_result_status (
                  result,
                  "skipped",
                  "HTTP/2 request compression unavailable in this runtime");
            }
          else
            {
              set_result_status (result,
                                 "error",
                                 SocketGRPC_Status_message (&status));
            }
          goto cleanup;
        }

      latencies[i] = latency_ms;
      sum_ms += latency_ms;
      result->successes++;
    }

  qsort (latencies, (size_t)result->successes, sizeof (double), double_compare);

  if (result->successes > 0)
    {
      result->avg_ms = sum_ms / (double)result->successes;
      result->p50_ms = percentile (latencies, (size_t)result->successes, 50.0);
      result->p95_ms = percentile (latencies, (size_t)result->successes, 95.0);
      result->p99_ms = percentile (latencies, (size_t)result->successes, 99.0);
      if (sum_ms > 0.0)
        result->throughput_rps
            = ((double)result->successes / sum_ms) * 1000.0;
    }

  set_result_status (result, "ok", "");

cleanup:
  fixture_stop (&fixture);
  free (payload);
  free (latencies);
}

static int
build_scenarios (const BenchConfig *cfg,
                 BenchScenario *out,
                 size_t out_cap,
                 size_t *out_count)
{
  size_t payload_sizes[3];
  size_t payload_count = 0;
  size_t count = 0;
  size_t i;

  if (cfg == NULL || out == NULL || out_count == NULL)
    return -1;

  if (cfg->smoke)
    {
      payload_sizes[0] = 128;
      payload_sizes[1] = 4096;
      payload_count = 2;
    }
  else
    {
      payload_sizes[0] = 128;
      payload_sizes[1] = 4096;
      payload_sizes[2] = 65536;
      payload_count = 3;
    }

  for (i = 0; i < payload_count; i++)
    {
      if (count >= out_cap)
        return -1;
      out[count].id = "h2_unary";
      out[count].mode = SOCKET_GRPC_CHANNEL_MODE_HTTP2;
      out[count].payload_bytes = payload_sizes[i];
      out[count].request_compression = 0;
      count++;
    }

  if (count + 2 > out_cap)
    return -1;
  out[count].id = "h2_compression";
  out[count].mode = SOCKET_GRPC_CHANNEL_MODE_HTTP2;
  out[count].payload_bytes = 4096;
  out[count].request_compression = 1;
  count++;

  for (i = 0; i < payload_count; i++)
    {
      if (count >= out_cap)
        return -1;
      out[count].id = "h3_unary";
      out[count].mode = SOCKET_GRPC_CHANNEL_MODE_HTTP3;
      out[count].payload_bytes = payload_sizes[i];
      out[count].request_compression = 0;
      count++;
    }

  if (count >= out_cap)
    return -1;
  out[count].id = "h3_compression";
  out[count].mode = SOCKET_GRPC_CHANNEL_MODE_HTTP3;
  out[count].payload_bytes = 4096;
  out[count].request_compression = 1;
  count++;

  *out_count = count;
  return 0;
}

#endif /* SOCKET_HAS_TLS */

static void
write_report (FILE *out,
              const BenchConfig *cfg,
              const BenchResult *results,
              size_t result_count)
{
  struct utsname sys;
  char timestamp[40];
  char host[128] = "unknown";
  long cpus = sysconf (_SC_NPROCESSORS_ONLN);
  size_t i;
  int ok_count = 0;
  int skipped_count = 0;
  int unsupported_count = 0;
  int error_count = 0;

  if (out == NULL || cfg == NULL)
    return;

  memset (&sys, 0, sizeof (sys));
  (void)uname (&sys);
  (void)gethostname (host, sizeof (host) - 1U);
  host[sizeof (host) - 1U] = '\0';
  iso8601_now_utc (timestamp, sizeof (timestamp));

  for (i = 0; i < result_count; i++)
    {
      if (strcmp (results[i].status, "ok") == 0)
        ok_count++;
      else if (strcmp (results[i].status, "skipped") == 0)
        skipped_count++;
      else if (strcmp (results[i].status, "unsupported") == 0)
        unsupported_count++;
      else
        error_count++;
    }

  fprintf (out, "{\n");
  fprintf (out, "  \"profile\": ");
  json_print_string (out, cfg->smoke ? "smoke" : "full");
  fprintf (out, ",\n");
  fprintf (out, "  \"generated_at\": ");
  json_print_string (out, timestamp);
  fprintf (out, ",\n");
  fprintf (out, "  \"environment\": {\n");
  fprintf (out, "    \"hostname\": ");
  json_print_string (out, host);
  fprintf (out, ",\n");
  fprintf (out, "    \"sysname\": ");
  json_print_string (out, sys.sysname[0] ? sys.sysname : "unknown");
  fprintf (out, ",\n");
  fprintf (out, "    \"release\": ");
  json_print_string (out, sys.release[0] ? sys.release : "unknown");
  fprintf (out, ",\n");
  fprintf (out, "    \"machine\": ");
  json_print_string (out, sys.machine[0] ? sys.machine : "unknown");
  fprintf (out, ",\n");
  fprintf (out, "    \"cpu_count\": %ld,\n", cpus > 0 ? cpus : 1);
  fprintf (out, "    \"tls_enabled\": %d\n", (int)SOCKET_HAS_TLS);
  fprintf (out, "  },\n");
  fprintf (out, "  \"config\": {\n");
  fprintf (out, "    \"iterations\": %d,\n", cfg->iterations);
  fprintf (out, "    \"warmup\": %d\n", cfg->warmup);
  fprintf (out, "  },\n");
  fprintf (out, "  \"summary\": {\n");
  fprintf (out, "    \"total\": %zu,\n", result_count);
  fprintf (out, "    \"ok\": %d,\n", ok_count);
  fprintf (out, "    \"skipped\": %d,\n", skipped_count);
  fprintf (out, "    \"unsupported\": %d,\n", unsupported_count);
  fprintf (out, "    \"error\": %d\n", error_count);
  fprintf (out, "  },\n");
  fprintf (out, "  \"results\": [\n");

  for (i = 0; i < result_count; i++)
    {
      const BenchResult *r = &results[i];
      fprintf (out, "    {\n");
      fprintf (out, "      \"id\": ");
      json_print_string (out, r->spec.id);
      fprintf (out, ",\n");
      fprintf (out, "      \"transport\": ");
      json_print_string (
          out,
          (r->spec.mode == SOCKET_GRPC_CHANNEL_MODE_HTTP3) ? "http3" : "http2");
      fprintf (out, ",\n");
      fprintf (out, "      \"payload_bytes\": %zu,\n", r->spec.payload_bytes);
      fprintf (out,
               "      \"request_compression\": %s,\n",
               r->spec.request_compression ? "true" : "false");
      fprintf (out, "      \"status\": ");
      json_print_string (out, r->status);
      fprintf (out, ",\n");
      fprintf (out, "      \"note\": ");
      json_print_string (out, r->note);
      fprintf (out, ",\n");
      fprintf (out, "      \"iterations\": %d,\n", r->iterations);
      fprintf (out, "      \"warmup\": %d,\n", r->warmup);
      fprintf (out, "      \"successes\": %d,\n", r->successes);
      fprintf (out, "      \"avg_latency_ms\": %.6f,\n", r->avg_ms);
      fprintf (out, "      \"p50_latency_ms\": %.6f,\n", r->p50_ms);
      fprintf (out, "      \"p95_latency_ms\": %.6f,\n", r->p95_ms);
      fprintf (out, "      \"p99_latency_ms\": %.6f,\n", r->p99_ms);
      fprintf (out, "      \"throughput_rps\": %.3f\n", r->throughput_rps);
      fprintf (out, "    }%s\n", (i + 1U < result_count) ? "," : "");
    }

  fprintf (out, "  ]\n");
  fprintf (out, "}\n");
}

int
main (int argc, char **argv)
{
  BenchConfig cfg;
  int parse_rc;
  FILE *report = stdout;
  int exit_code = 0;

  parse_rc = parse_args (argc, argv, &cfg);
  if (parse_rc > 0)
    return 0;
  if (parse_rc < 0)
    return 2;

#if SOCKET_HAS_TLS
  {
    BenchScenario scenarios[BENCH_MAX_SCENARIOS];
    BenchResult results[BENCH_MAX_SCENARIOS];
    size_t scenario_count = 0;
    size_t i;

    if (build_scenarios (&cfg,
                         scenarios,
                         sizeof (scenarios) / sizeof (scenarios[0]),
                         &scenario_count)
        != 0)
      {
        fprintf (stderr, "failed to build scenario matrix\n");
        return 1;
      }

    for (i = 0; i < scenario_count; i++)
      {
        run_scenario (&scenarios[i], &cfg, &results[i]);
        if (scenarios[i].mode == SOCKET_GRPC_CHANNEL_MODE_HTTP2
            && !scenarios[i].request_compression
            && strcmp (results[i].status, "ok") != 0)
          exit_code = 1;
      }

    if (cfg.report_path != NULL)
      {
        report = fopen (cfg.report_path, "w");
        if (report == NULL)
          {
            fprintf (stderr, "failed to open report path: %s\n", cfg.report_path);
            return 1;
          }
      }

    write_report (report, &cfg, results, scenario_count);

    if (report != stdout)
      fclose (report);
  }
#else
  {
    BenchResult result;

    memset (&result, 0, sizeof (result));
    result.spec.id = "grpc_benchmark";
    result.spec.mode = SOCKET_GRPC_CHANNEL_MODE_HTTP2;
    result.spec.payload_bytes = 0;
    result.spec.request_compression = 0;
    snprintf (result.status, sizeof (result.status), "skipped");
    snprintf (result.note,
              sizeof (result.note),
              "TLS is disabled; gRPC transport benchmark unavailable");

    if (cfg.report_path != NULL)
      {
        report = fopen (cfg.report_path, "w");
        if (report == NULL)
          {
            fprintf (stderr, "failed to open report path: %s\n", cfg.report_path);
            return 1;
          }
      }

    write_report (report, &cfg, &result, 1);

    if (report != stdout)
      fclose (report);
  }
#endif

  return exit_code;
}

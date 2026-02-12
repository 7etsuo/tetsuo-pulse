/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_grpc_api_surface.c
 * @brief Compile/link smoke tests for gRPC API scaffolding.
 */

#include "grpc/SocketGRPC.h"
#include "test/Test.h"

#include <stdint.h>
#include <string.h>

TEST (grpc_status_code_names_cover_canonical_space)
{
  for (int i = SOCKET_GRPC_STATUS_OK; i <= SOCKET_GRPC_STATUS_UNAUTHENTICATED;
       i++)
    {
      const char *name = SocketGRPC_Status_code_name ((SocketGRPC_StatusCode)i);
      ASSERT_NOT_NULL (name);
      ASSERT_NE (0, strcmp (name, "UNKNOWN_CODE"));
    }
}

TEST (grpc_status_accessors_are_null_safe)
{
  ASSERT_EQ (SOCKET_GRPC_STATUS_INTERNAL, SocketGRPC_Status_code (NULL));
  ASSERT_NOT_NULL (SocketGRPC_Status_message (NULL));
  ASSERT_EQ (0,
             strcmp (SocketGRPC_Status_code_name ((SocketGRPC_StatusCode)1024),
                     "UNKNOWN_CODE"));
}

TEST (grpc_status_accessors_support_custom_and_default_messages)
{
  SocketGRPC_Status custom
      = { SOCKET_GRPC_STATUS_UNAVAILABLE, "upstream reset by peer" };
  SocketGRPC_Status fallback = { SOCKET_GRPC_STATUS_NOT_FOUND, NULL };

  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE, SocketGRPC_Status_code (&custom));
  ASSERT_EQ (
      0,
      strcmp (SocketGRPC_Status_message (&custom), "upstream reset by peer"));

  ASSERT_EQ (SOCKET_GRPC_STATUS_NOT_FOUND, SocketGRPC_Status_code (&fallback));
  ASSERT_EQ (0,
             strcmp (SocketGRPC_Status_message (&fallback),
                     "Requested entity was not found"));
}

TEST (grpc_timeout_parse_and_format_helpers)
{
  char timeout_buf[32];
  int64_t timeout_ms = 0;

  ASSERT_EQ (
      0, SocketGRPC_Timeout_format (2500, timeout_buf, sizeof (timeout_buf)));
  ASSERT_EQ (0, strcmp (timeout_buf, "2500m"));

  ASSERT_EQ (0, SocketGRPC_Timeout_parse ("2500m", &timeout_ms));
  ASSERT_EQ (2500, timeout_ms);
  ASSERT_EQ (0, SocketGRPC_Timeout_parse ("2S", &timeout_ms));
  ASSERT_EQ (2000, timeout_ms);
  ASSERT_EQ (0, SocketGRPC_Timeout_parse ("1M", &timeout_ms));
  ASSERT_EQ (60000, timeout_ms);
  ASSERT_EQ (0, SocketGRPC_Timeout_parse ("1500u", &timeout_ms));
  ASSERT_EQ (2, timeout_ms);
  ASSERT_EQ (0, SocketGRPC_Timeout_parse ("2500000n", &timeout_ms));
  ASSERT_EQ (3, timeout_ms);

  ASSERT_EQ (-1,
             SocketGRPC_Timeout_format (0, timeout_buf, sizeof (timeout_buf)));
  ASSERT_EQ (-1, SocketGRPC_Timeout_parse ("", &timeout_ms));
  ASSERT_EQ (-1, SocketGRPC_Timeout_parse ("10", &timeout_ms));
  ASSERT_EQ (-1, SocketGRPC_Timeout_parse ("10x", &timeout_ms));
  ASSERT_EQ (-1, SocketGRPC_Timeout_parse ("-10m", &timeout_ms));
}

TEST (grpc_retry_policy_parse_and_validation)
{
  SocketGRPC_RetryPolicy policy;

  SocketGRPC_RetryPolicy_defaults (&policy);
  ASSERT_EQ (0, SocketGRPC_RetryPolicy_validate (&policy));
  ASSERT_EQ (1, policy.max_attempts);
  ASSERT_EQ (100, policy.initial_backoff_ms);
  ASSERT_EQ (1000, policy.max_backoff_ms);

  ASSERT_EQ (0,
             SocketGRPC_RetryPolicy_parse_service_config (
                 "max_attempts=3,initial_backoff_ms=20,max_backoff_ms=200,"
                 "multiplier=2.5,jitter_percent=15,"
                 "retryable_codes=UNAVAILABLE|RESOURCE_EXHAUSTED",
                 &policy));
  ASSERT_EQ (3, policy.max_attempts);
  ASSERT_EQ (20, policy.initial_backoff_ms);
  ASSERT_EQ (200, policy.max_backoff_ms);
  ASSERT_EQ (15, policy.jitter_percent);
  ASSERT (
      (policy.retryable_status_mask & (1U << SOCKET_GRPC_STATUS_UNAVAILABLE))
      != 0);
  ASSERT ((policy.retryable_status_mask
           & (1U << SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED))
          != 0);

  ASSERT_EQ (
      -1,
      SocketGRPC_RetryPolicy_parse_service_config ("max_attempts=0", &policy));
  ASSERT_EQ (
      -1,
      SocketGRPC_RetryPolicy_parse_service_config ("max_attempts=3x", &policy));
  ASSERT_EQ (
      -1,
      SocketGRPC_RetryPolicy_parse_service_config ("multiplier=nan", &policy));
  ASSERT_EQ (-1,
             SocketGRPC_RetryPolicy_parse_service_config (
                 "retryable_codes=NOPE", &policy));
}

TEST (grpc_handle_lifecycle_smoke)
{
  SocketGRPC_ClientConfig client_cfg;
  SocketGRPC_ServerConfig server_cfg;
  SocketGRPC_ChannelConfig channel_cfg;
  SocketGRPC_CallConfig call_cfg;

  SocketGRPC_ClientConfig_defaults (&client_cfg);
  SocketGRPC_ServerConfig_defaults (&server_cfg);
  SocketGRPC_ChannelConfig_defaults (&channel_cfg);
  SocketGRPC_CallConfig_defaults (&call_cfg);

  SocketGRPC_Client_T client = SocketGRPC_Client_new (&client_cfg);
  SocketGRPC_Server_T server = SocketGRPC_Server_new (&server_cfg);
  SocketGRPC_Channel_T channel
      = SocketGRPC_Channel_new (client, "dns:///example.grpc.local", NULL);
  SocketGRPC_Call_T call
      = SocketGRPC_Call_new (channel, "/example.Service/Ping", &call_cfg);

  ASSERT_NOT_NULL (client);
  ASSERT_NOT_NULL (server);
  ASSERT_NOT_NULL (channel);
  ASSERT_NOT_NULL (call);

  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Server_free (&server);
  SocketGRPC_Client_free (&client);

  ASSERT_NULL (call);
  ASSERT_NULL (channel);
  ASSERT_NULL (server);
  ASSERT_NULL (client);
}

static int
noop_unary_handler (SocketGRPC_ServerContext_T ctx,
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
  return SOCKET_GRPC_STATUS_OK;
}

static void
noop_unary_handler_except (SocketGRPC_ServerContext_T ctx,
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
}

typedef struct
{
  int client_unary_events;
  int stream_send_events;
  int stream_recv_events;
} InterceptorProbe;

static int
test_unary_continue_interceptor (SocketGRPC_Call_T call,
                                 const uint8_t *request_payload,
                                 size_t request_payload_len,
                                 SocketGRPC_Status *status_io,
                                 void *userdata)
{
  InterceptorProbe *probe = (InterceptorProbe *)userdata;
  (void)call;
  (void)request_payload;
  (void)request_payload_len;
  (void)status_io;
  if (probe != NULL)
    probe->client_unary_events++;
  return SOCKET_GRPC_INTERCEPT_CONTINUE;
}

static int
test_unary_stop_interceptor (SocketGRPC_Call_T call,
                             const uint8_t *request_payload,
                             size_t request_payload_len,
                             SocketGRPC_Status *status_io,
                             void *userdata)
{
  (void)call;
  (void)request_payload;
  (void)request_payload_len;
  (void)userdata;
  if (status_io != NULL)
    {
      status_io->code = SOCKET_GRPC_STATUS_UNAUTHENTICATED;
      status_io->message = "blocked by unary interceptor";
    }
  return SOCKET_GRPC_INTERCEPT_STOP;
}

static int
test_stream_probe_interceptor (SocketGRPC_Call_T call,
                               SocketGRPC_StreamInterceptEvent event,
                               const uint8_t *payload,
                               size_t payload_len,
                               SocketGRPC_Status *status_io,
                               void *userdata)
{
  InterceptorProbe *probe = (InterceptorProbe *)userdata;
  (void)call;
  (void)payload;
  (void)payload_len;
  (void)status_io;
  if (probe == NULL)
    return SOCKET_GRPC_INTERCEPT_CONTINUE;
  if (event == SOCKET_GRPC_STREAM_INTERCEPT_SEND)
    probe->stream_send_events++;
  else if (event == SOCKET_GRPC_STREAM_INTERCEPT_RECV)
    probe->stream_recv_events++;
  return SOCKET_GRPC_INTERCEPT_CONTINUE;
}

static int
test_stream_stop_interceptor (SocketGRPC_Call_T call,
                              SocketGRPC_StreamInterceptEvent event,
                              const uint8_t *payload,
                              size_t payload_len,
                              SocketGRPC_Status *status_io,
                              void *userdata)
{
  (void)call;
  (void)payload;
  (void)payload_len;
  (void)userdata;
  if (event != SOCKET_GRPC_STREAM_INTERCEPT_SEND)
    return SOCKET_GRPC_INTERCEPT_CONTINUE;
  if (status_io != NULL)
    {
      status_io->code = SOCKET_GRPC_STATUS_UNAUTHENTICATED;
      status_io->message = "blocked by stream interceptor";
    }
  return SOCKET_GRPC_INTERCEPT_STOP;
}

static void
test_log_hook (const SocketGRPC_LogEvent *event, void *userdata)
{
  InterceptorProbe *probe = (InterceptorProbe *)userdata;
  if (probe == NULL || event == NULL)
    return;
  if (event->type == SOCKET_GRPC_LOG_EVENT_CLIENT_UNARY)
    probe->client_unary_events++;
}

static int
test_server_continue_interceptor (SocketGRPC_ServerContext_T ctx,
                                  const uint8_t *request_payload,
                                  size_t request_payload_len,
                                  SocketGRPC_Status *status_io,
                                  void *userdata)
{
  (void)ctx;
  (void)request_payload;
  (void)request_payload_len;
  (void)status_io;
  (void)userdata;
  return SOCKET_GRPC_INTERCEPT_CONTINUE;
}

TEST (grpc_server_registration_and_shutdown_surface)
{
  SocketGRPC_Server_T server = SocketGRPC_Server_new (NULL);
  ASSERT_NOT_NULL (server);

  ASSERT_EQ (0,
             SocketGRPC_Server_register_unary (
                 server, "/test.Service/Ping", noop_unary_handler, NULL));
  ASSERT_EQ (-1,
             SocketGRPC_Server_register_unary (
                 server, "/test.Service/Ping", noop_unary_handler, NULL));
  ASSERT_EQ (-1,
             SocketGRPC_Server_register_unary (
                 server, "/bad-path", noop_unary_handler, NULL));
  ASSERT_EQ (
      0,
      SocketGRPC_Server_register_unary_except (
          server, "/test.Service/PingEx", noop_unary_handler_except, NULL));

  ASSERT_EQ (0U, SocketGRPC_Server_inflight_calls (server));
  SocketGRPC_Server_begin_shutdown (server);
  ASSERT_EQ (0U, SocketGRPC_Server_inflight_calls (server));

  SocketGRPC_Server_free (&server);
  ASSERT_NULL (server);
}

TEST (grpc_server_context_accessors_are_null_safe)
{
  ASSERT_NULL (SocketGRPC_ServerContext_metadata (NULL));
  ASSERT_NULL (SocketGRPC_ServerContext_peer (NULL));
  ASSERT_NULL (SocketGRPC_ServerContext_full_method (NULL));
  ASSERT_NULL (SocketGRPC_ServerContext_service (NULL));
  ASSERT_NULL (SocketGRPC_ServerContext_method (NULL));
  ASSERT_EQ (1, SocketGRPC_ServerContext_is_cancelled (NULL));
  ASSERT_EQ (
      -1,
      SocketGRPC_ServerContext_set_status (NULL, SOCKET_GRPC_STATUS_OK, "x"));
  ASSERT_EQ (-1,
             SocketGRPC_ServerContext_set_status_details_bin (
                 NULL, (const uint8_t *)"x", 1));
  ASSERT_EQ (
      -1,
      SocketGRPC_ServerContext_add_trailing_metadata_ascii (NULL, "k", "v"));
  ASSERT_EQ (-1,
             SocketGRPC_ServerContext_add_trailing_metadata_binary (
                 NULL, "k-bin", (const uint8_t *)"v", 1));
}

TEST (grpc_invalid_inputs_fail_without_crash)
{
  SocketGRPC_Client_T client = SocketGRPC_Client_new (NULL);
  Arena_T arena = Arena_new ();
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int done = 0;
  ASSERT_NOT_NULL (client);
  ASSERT_NOT_NULL (arena);

  ASSERT_EQ (-1, SocketGRPC_Call_send_message (NULL, (const uint8_t *)"x", 1));
  ASSERT_EQ (-1, SocketGRPC_Call_close_send (NULL));
  ASSERT_EQ (-1, SocketGRPC_Call_cancel (NULL));
  ASSERT_EQ (-1, SocketGRPC_Call_recv_message (NULL, arena, NULL, NULL, NULL));

  ASSERT_NULL (SocketGRPC_Channel_new (NULL, "dns:///x", NULL));
  ASSERT_NULL (SocketGRPC_Channel_new (client, NULL, NULL));
  ASSERT_NULL (SocketGRPC_Channel_new (client, "", NULL));

  SocketGRPC_Channel_T channel
      = SocketGRPC_Channel_new (client, "dns:///x", NULL);
  ASSERT_NOT_NULL (channel);

  ASSERT_NULL (SocketGRPC_Call_new (NULL, "/svc/method", NULL));
  ASSERT_NULL (SocketGRPC_Call_new (channel, NULL, NULL));
  ASSERT_NULL (SocketGRPC_Call_new (channel, "", NULL));

  {
    SocketGRPC_Call_T call
        = SocketGRPC_Call_new (channel, "/svc.Method/Stream", NULL);
    ASSERT_NOT_NULL (call);
    ASSERT_EQ (-1, SocketGRPC_Call_send_message (call, NULL, 1));
    ASSERT_EQ (0, SocketGRPC_Call_cancel (call));
    ASSERT_EQ (SOCKET_GRPC_STATUS_CANCELLED,
               SocketGRPC_Call_status (call).code);
    ASSERT_EQ (
        -1,
        SocketGRPC_Call_recv_message (
            call, arena, &response_payload, &response_payload_len, &done));
    SocketGRPC_Call_free (&call);
  }

  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
  Arena_dispose (&arena);
}

TEST (grpc_interceptor_api_and_short_circuit_surface)
{
  SocketGRPC_Client_T client = NULL;
  SocketGRPC_Server_T server = NULL;
  SocketGRPC_Channel_T channel = NULL;
  SocketGRPC_Call_T call = NULL;
  Arena_T arena = NULL;
  SocketGRPC_CallConfig call_cfg;
  SocketGRPC_LogHookConfig log_cfg;
  SocketGRPC_MetadataInjectorConfig md_cfg;
  InterceptorProbe probe = { 0 };
  uint8_t request_payload[] = { 0x08, 0x01 };
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int rc;

  SocketGRPC_CallConfig_defaults (&call_cfg);
  call_cfg.deadline_ms = 25;

  client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);
  server = SocketGRPC_Server_new (NULL);
  ASSERT_NOT_NULL (server);
  channel = SocketGRPC_Channel_new (client, "https://127.0.0.1:1", NULL);
  ASSERT_NOT_NULL (channel);
  call = SocketGRPC_Call_new (channel, "/test.Service/Unary", &call_cfg);
  ASSERT_NOT_NULL (call);
  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  ASSERT_EQ (-1,
             SocketGRPC_Call_add_unary_interceptor (
                 NULL, test_unary_continue_interceptor, &probe));
  ASSERT_EQ (-1,
             SocketGRPC_Call_add_stream_interceptor (
                 NULL, test_stream_probe_interceptor, &probe));
  ASSERT_EQ (-1,
             SocketGRPC_Server_add_unary_interceptor (
                 NULL, test_server_continue_interceptor, NULL));

  ASSERT_EQ (0,
             SocketGRPC_Call_add_unary_interceptor (
                 call, test_unary_continue_interceptor, &probe));
  ASSERT_EQ (0,
             SocketGRPC_Call_add_stream_interceptor (
                 call, test_stream_probe_interceptor, &probe));
  ASSERT_EQ (0,
             SocketGRPC_Call_add_stream_interceptor (
                 call, test_stream_stop_interceptor, NULL));
  ASSERT_EQ (0,
             SocketGRPC_Server_add_unary_interceptor (
                 server, test_server_continue_interceptor, NULL));

  md_cfg.key = "x-client-id";
  md_cfg.ascii_value = "surface-test";
  md_cfg.binary_value = NULL;
  md_cfg.binary_value_len = 0;
  md_cfg.is_binary = 0;
  {
    SocketGRPC_Status st = { SOCKET_GRPC_STATUS_OK, NULL };
    ASSERT_EQ (
        SOCKET_GRPC_INTERCEPT_CONTINUE,
        SocketGRPC_Interceptor_metadata_injector (
            call, request_payload, sizeof (request_payload), &st, &md_cfg));
  }

  md_cfg.key = "grpc-timeout";
  {
    SocketGRPC_Status st = { SOCKET_GRPC_STATUS_OK, NULL };
    ASSERT_EQ (
        SOCKET_GRPC_INTERCEPT_STOP,
        SocketGRPC_Interceptor_metadata_injector (
            call, request_payload, sizeof (request_payload), &st, &md_cfg));
    ASSERT_EQ (SOCKET_GRPC_STATUS_INVALID_ARGUMENT, st.code);
  }

  log_cfg.hook = test_log_hook;
  log_cfg.hook_userdata = &probe;
  {
    SocketGRPC_Status st = { SOCKET_GRPC_STATUS_OK, NULL };
    ASSERT_EQ (
        SOCKET_GRPC_INTERCEPT_CONTINUE,
        SocketGRPC_Interceptor_client_logging (
            call, request_payload, sizeof (request_payload), &st, &log_cfg));
  }
  ASSERT_EQ (1, probe.client_unary_events);

  ASSERT_EQ (0,
             SocketGRPC_Call_add_unary_interceptor (
                 call, test_unary_stop_interceptor, NULL));

  rc = SocketGRPC_Call_unary_h2 (call,
                                 request_payload,
                                 sizeof (request_payload),
                                 arena,
                                 &response_payload,
                                 &response_payload_len);
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAUTHENTICATED, rc);
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAUTHENTICATED,
             SocketGRPC_Call_status (call).code);
  ASSERT_NULL (response_payload);
  ASSERT_EQ (0U, response_payload_len);

  rc = SocketGRPC_Call_send_message (
      call, request_payload, sizeof (request_payload));
  ASSERT_EQ (-1, rc);
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAUTHENTICATED,
             SocketGRPC_Call_status (call).code);
  ASSERT_EQ (1, probe.stream_send_events);

  Arena_dispose (&arena);
  SocketGRPC_Call_free (&call);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Server_free (&server);
  SocketGRPC_Client_free (&client);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

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
  ASSERT_EQ (
      0,
      strcmp (SocketGRPC_Status_code_name ((SocketGRPC_StatusCode)1024),
              "UNKNOWN_CODE"));
}

TEST (grpc_status_accessors_support_custom_and_default_messages)
{
  SocketGRPC_Status custom
      = { SOCKET_GRPC_STATUS_UNAVAILABLE, "upstream reset by peer" };
  SocketGRPC_Status fallback = { SOCKET_GRPC_STATUS_NOT_FOUND, NULL };

  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE, SocketGRPC_Status_code (&custom));
  ASSERT_EQ (0, strcmp (SocketGRPC_Status_message (&custom),
                        "upstream reset by peer"));

  ASSERT_EQ (SOCKET_GRPC_STATUS_NOT_FOUND, SocketGRPC_Status_code (&fallback));
  ASSERT_EQ (0, strcmp (SocketGRPC_Status_message (&fallback),
                        "Requested entity was not found"));
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

TEST (grpc_invalid_inputs_fail_without_crash)
{
  SocketGRPC_Client_T client = SocketGRPC_Client_new (NULL);
  ASSERT_NOT_NULL (client);

  ASSERT_NULL (SocketGRPC_Channel_new (NULL, "dns:///x", NULL));
  ASSERT_NULL (SocketGRPC_Channel_new (client, NULL, NULL));
  ASSERT_NULL (SocketGRPC_Channel_new (client, "", NULL));

  SocketGRPC_Channel_T channel
      = SocketGRPC_Channel_new (client, "dns:///x", NULL);
  ASSERT_NOT_NULL (channel);

  ASSERT_NULL (SocketGRPC_Call_new (NULL, "/svc/method", NULL));
  ASSERT_NULL (SocketGRPC_Call_new (channel, NULL, NULL));
  ASSERT_NULL (SocketGRPC_Call_new (channel, "", NULL));

  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&client);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

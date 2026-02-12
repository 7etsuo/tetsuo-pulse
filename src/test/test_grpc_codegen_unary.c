/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "core/Arena.h"
#include "grpc/SocketGRPC.h"
#include "test/Test.h"
#include "unary.socketgrpc.h"

#include <string.h>

static int
handle_say_hello (const test_unary_HelloRequest *request,
                  test_unary_HelloResponse *response,
                  void *userdata,
                  Arena_T arena)
{
  (void)arena;
  (void)userdata;
  if (request == NULL || response == NULL || request->name == NULL)
    return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;

  response->greeting = request->name;
  response->code = request->id + 1000U;
  return SOCKET_GRPC_STATUS_OK;
}

TEST (grpc_codegen_unary_message_roundtrip)
{
  test_unary_HelloRequest request;
  test_unary_HelloRequest decoded;
  uint8_t wire[256];
  size_t written = 0;
  Arena_T arena = Arena_new ();

  test_unary_HelloRequest_init (&request);
  test_unary_HelloRequest_init (&decoded);

  request.name = "Ada";
  request.id = 42;

  ASSERT_EQ (0, test_unary_HelloRequest_encode (
                    &request, wire, sizeof (wire), &written));
  ASSERT_NE (0U, written);
  ASSERT_EQ (0, test_unary_HelloRequest_decode (&decoded, wire, written, arena));
  ASSERT_NOT_NULL (decoded.name);
  ASSERT_EQ (0, strcmp (decoded.name, "Ada"));
  ASSERT_EQ (42U, decoded.id);

  test_unary_HelloRequest_free (&decoded);
  test_unary_HelloRequest_free (&request);
  Arena_dispose (&arena);
}

TEST (grpc_codegen_unary_local_handler_invocation)
{
  SocketGRPC_Client_T core_client = SocketGRPC_Client_new (NULL);
  SocketGRPC_Channel_T channel;
  Arena_T arena = Arena_new ();
  test_unary_Greeter_Client client;
  test_unary_Greeter_ServerHandlers handlers;
  test_unary_HelloRequest request;
  test_unary_HelloResponse response;

  ASSERT_NOT_NULL (core_client);
  channel = SocketGRPC_Channel_new (core_client, "dns:///unary.local", NULL);
  ASSERT_NOT_NULL (channel);

  memset (&handlers, 0, sizeof (handlers));
  handlers.SayHello = handle_say_hello;

  test_unary_Greeter_Client_init (&client, channel);
  test_unary_Greeter_Client_bind_local (&client, &handlers);

  test_unary_HelloRequest_init (&request);
  test_unary_HelloResponse_init (&response);
  request.name = "Grace";
  request.id = 7;

  ASSERT_EQ (SOCKET_GRPC_STATUS_OK,
             test_unary_Greeter_Client_SayHello (
                 &client, &request, &response, arena));
  ASSERT_NOT_NULL (response.greeting);
  ASSERT_EQ (0, strcmp (response.greeting, "Grace"));
  ASSERT_EQ (1007U, response.code);

  test_unary_HelloResponse_free (&response);
  test_unary_HelloRequest_free (&request);
  SocketGRPC_Channel_free (&channel);
  SocketGRPC_Client_free (&core_client);
  Arena_dispose (&arena);
}

TEST (grpc_codegen_unary_unbound_handler_returns_unimplemented)
{
  test_unary_Greeter_Client client;
  test_unary_HelloRequest request;
  test_unary_HelloResponse response;
  Arena_T arena = Arena_new ();

  test_unary_Greeter_Client_init (&client, NULL);
  test_unary_HelloRequest_init (&request);
  test_unary_HelloResponse_init (&response);
  request.name = "NoHandler";
  request.id = 1;

  ASSERT_EQ (SOCKET_GRPC_STATUS_UNIMPLEMENTED,
             test_unary_Greeter_Client_SayHello (
                 &client, &request, &response, arena));

  test_unary_HelloResponse_free (&response);
  test_unary_HelloRequest_free (&request);
  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "core/Arena.h"
#include "grpc/SocketGRPC.h"
#include "streaming.socketgrpc.h"
#include "test/Test.h"

#include <string.h>

typedef struct
{
  int upload_calls;
  int subscribe_calls;
  int chat_calls;
  int last_stream_id;
} StreamStats;

static int
handle_upload_stream (void *stream_ctx, void *userdata, Arena_T arena)
{
  StreamStats *stats = (StreamStats *)userdata;
  const int *stream_id = (const int *)stream_ctx;
  (void)arena;
  if (stats == NULL || stream_id == NULL)
    return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;
  stats->upload_calls++;
  stats->last_stream_id = *stream_id;
  return SOCKET_GRPC_STATUS_OK;
}

static int
handle_subscribe_stream (void *stream_ctx, void *userdata, Arena_T arena)
{
  StreamStats *stats = (StreamStats *)userdata;
  const int *stream_id = (const int *)stream_ctx;
  (void)arena;
  if (stats == NULL || stream_id == NULL)
    return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;
  stats->subscribe_calls++;
  stats->last_stream_id = *stream_id;
  return SOCKET_GRPC_STATUS_CANCELLED;
}

static int
handle_chat_stream (void *stream_ctx, void *userdata, Arena_T arena)
{
  StreamStats *stats = (StreamStats *)userdata;
  const int *stream_id = (const int *)stream_ctx;
  (void)arena;
  if (stats == NULL || stream_id == NULL)
    return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;
  stats->chat_calls++;
  stats->last_stream_id = *stream_id;
  return SOCKET_GRPC_STATUS_OK;
}

TEST (grpc_codegen_streaming_message_roundtrip)
{
  test_streaming_Chunk chunk;
  test_streaming_Chunk decoded;
  uint8_t payload[] = { 0xAA, 0xBB, 0xCC, 0xDD };
  uint8_t wire[256];
  size_t written = 0;
  Arena_T arena = Arena_new ();

  test_streaming_Chunk_init (&chunk);
  test_streaming_Chunk_init (&decoded);
  chunk.data = payload;
  chunk.data_len = sizeof (payload);
  chunk.sequence = 11;

  ASSERT_EQ (
      0, test_streaming_Chunk_encode (&chunk, wire, sizeof (wire), &written));
  ASSERT_NE (0U, written);
  ASSERT_EQ (0, test_streaming_Chunk_decode (&decoded, wire, written, arena));
  ASSERT_EQ (11U, decoded.sequence);
  ASSERT_EQ (sizeof (payload), decoded.data_len);
  ASSERT_EQ (0, memcmp (decoded.data, payload, sizeof (payload)));

  test_streaming_Chunk_free (&decoded);
  test_streaming_Chunk_free (&chunk);
  Arena_dispose (&arena);
}

TEST (grpc_codegen_streaming_local_handlers)
{
  test_streaming_Streamer_Client client;
  test_streaming_Streamer_ServerHandlers handlers;
  StreamStats stats = { 0 };
  Arena_T arena = Arena_new ();
  int stream_id = 99;

  memset (&handlers, 0, sizeof (handlers));
  handlers.Upload_stream = handle_upload_stream;
  handlers.Subscribe_stream = handle_subscribe_stream;
  handlers.Chat_stream = handle_chat_stream;
  handlers.userdata = &stats;

  test_streaming_Streamer_Client_init (&client, NULL);
  test_streaming_Streamer_Client_bind_local (&client, &handlers);

  ASSERT_EQ (SOCKET_GRPC_STATUS_OK,
             test_streaming_Streamer_Client_Upload_stream (
                 &client, &stream_id, arena));
  ASSERT_EQ (SOCKET_GRPC_STATUS_CANCELLED,
             test_streaming_Streamer_Client_Subscribe_stream (
                 &client, &stream_id, arena));
  ASSERT_EQ (
      SOCKET_GRPC_STATUS_OK,
      test_streaming_Streamer_Client_Chat_stream (&client, &stream_id, arena));

  ASSERT_EQ (1, stats.upload_calls);
  ASSERT_EQ (1, stats.subscribe_calls);
  ASSERT_EQ (1, stats.chat_calls);
  ASSERT_EQ (99, stats.last_stream_id);

  Arena_dispose (&arena);
}

TEST (grpc_codegen_streaming_unbound_handlers_return_unimplemented)
{
  test_streaming_Streamer_Client client;
  Arena_T arena = Arena_new ();
  int stream_id = 5;

  test_streaming_Streamer_Client_init (&client, NULL);

  ASSERT_EQ (SOCKET_GRPC_STATUS_UNIMPLEMENTED,
             test_streaming_Streamer_Client_Upload_stream (
                 &client, &stream_id, arena));
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNIMPLEMENTED,
             test_streaming_Streamer_Client_Subscribe_stream (
                 &client, &stream_id, arena));
  ASSERT_EQ (
      SOCKET_GRPC_STATUS_UNIMPLEMENTED,
      test_streaming_Streamer_Client_Chat_stream (&client, &stream_id, arena));

  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

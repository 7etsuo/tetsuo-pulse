/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "grpc/SocketGRPCWire.h"
#include "test/Test.h"

#include <string.h>

TEST (grpc_wire_frame_roundtrip)
{
  uint8_t payload[] = { 0x01, 0x02, 0xA5, 0xFF, 0x10 };
  uint8_t frame[64];
  size_t written = 0;
  size_t consumed = 0;
  SocketGRPC_FrameView view;

  ASSERT_EQ (SOCKET_GRPC_WIRE_OK,
             SocketGRPC_Frame_encode (
                 1, payload, sizeof (payload), frame, sizeof (frame), &written));
  ASSERT_EQ (SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + sizeof (payload), written);
  ASSERT_EQ (SOCKET_GRPC_WIRE_OK,
             SocketGRPC_Frame_parse (
                 frame, written, sizeof (payload), &view, &consumed));
  ASSERT_EQ (written, consumed);
  ASSERT_EQ (1, view.compressed);
  ASSERT_EQ (sizeof (payload), view.payload_len);
  ASSERT_EQ (0, memcmp (payload, view.payload, sizeof (payload)));
}

TEST (grpc_wire_frame_rejects_invalid_prefixes_and_lengths)
{
  uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
  uint8_t frame[32];
  uint8_t invalid_flag[] = { 2, 0, 0, 0, 1, 0xAB };
  uint8_t truncated[] = { 0, 0, 0, 0, 8, 1, 2, 3 };
  size_t written = 0;
  size_t consumed = 0;
  SocketGRPC_FrameView view;

  ASSERT_EQ (SOCKET_GRPC_WIRE_INVALID_FRAME,
             SocketGRPC_Frame_encode (2,
                                      payload,
                                      sizeof (payload),
                                      frame,
                                      sizeof (frame),
                                      &written));
  ASSERT_EQ (SOCKET_GRPC_WIRE_BUFFER_TOO_SMALL,
             SocketGRPC_Frame_encode (
                 0, payload, sizeof (payload), frame, 4, &written));

  ASSERT_EQ (SOCKET_GRPC_WIRE_INVALID_FRAME,
             SocketGRPC_Frame_parse (
                 invalid_flag, sizeof (invalid_flag), 32, &view, &consumed));
  ASSERT_EQ (
      SOCKET_GRPC_WIRE_INCOMPLETE,
      SocketGRPC_Frame_parse (truncated, sizeof (truncated), 64, &view, &consumed));
  ASSERT_EQ (
      SOCKET_GRPC_WIRE_LENGTH_EXCEEDED,
      SocketGRPC_Frame_parse (truncated, sizeof (truncated), 4, &view, &consumed));
}

TEST (grpc_wire_http_status_mapping)
{
  ASSERT_EQ (SOCKET_GRPC_STATUS_OK, SocketGRPC_http_status_to_grpc (200));
  ASSERT_EQ (SOCKET_GRPC_STATUS_INTERNAL, SocketGRPC_http_status_to_grpc (400));
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAUTHENTICATED,
             SocketGRPC_http_status_to_grpc (401));
  ASSERT_EQ (SOCKET_GRPC_STATUS_PERMISSION_DENIED,
             SocketGRPC_http_status_to_grpc (403));
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNIMPLEMENTED,
             SocketGRPC_http_status_to_grpc (404));
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNAVAILABLE,
             SocketGRPC_http_status_to_grpc (503));
  ASSERT_EQ (SOCKET_GRPC_STATUS_UNKNOWN,
             SocketGRPC_http_status_to_grpc (418));
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

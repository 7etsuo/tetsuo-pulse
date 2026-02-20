/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_transport_peer_close.c
 * @brief Unit tests for SocketQUICTransport peer CONNECTION_CLOSE accessors.
 */

#include "core/Arena.h"
#include "quic/SocketQUICTransport.h"
#include "test/Test.h"

TEST (quic_transport_peer_close_defaults_zero)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICTransport_T t = SocketQUICTransport_new (arena, NULL);
  ASSERT_NOT_NULL (t);

  ASSERT_EQ (SocketQUICTransport_peer_close_received (t), 0);
  ASSERT_EQ (SocketQUICTransport_peer_close_error (t), 0);
  ASSERT_EQ (SocketQUICTransport_peer_close_is_app (t), 0);

  SocketQUICTransport_close (t);
  Arena_dispose (&arena);
}

TEST (quic_transport_peer_close_null_safety)
{
  ASSERT_EQ (SocketQUICTransport_peer_close_received (NULL), 0);
  ASSERT_EQ (SocketQUICTransport_peer_close_error (NULL), 0);
  ASSERT_EQ (SocketQUICTransport_peer_close_is_app (NULL), 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

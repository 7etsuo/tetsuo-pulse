/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_transport_0rtt_api.c
 * @brief Unit tests for SocketQUICTransport 0-RTT/resumption API validation.
 */

#include "core/Arena.h"
#include "quic/SocketQUICTransport.h"
#include "quic/SocketQUICTransportParams.h"
#include "test/Test.h"

#include <string.h>

static void
init_saved_peer_params (SocketQUICTransportParams_T *params)
{
  SocketQUICTransportParams_init (params);

  /* Populate a minimal, plausible set of peer params. */
  params->initial_max_data = 1048576;
  params->initial_max_stream_data_bidi_local = 262144;
  params->initial_max_stream_data_bidi_remote = 262144;
  params->initial_max_stream_data_uni = 262144;
  params->initial_max_streams_bidi = 100;
  params->initial_max_streams_uni = 3;
  params->active_connection_id_limit = 8;
  params->disable_active_migration = 0;
}

TEST (quic_transport_set_resumption_ticket_rejects_oversize)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICTransport_T t = SocketQUICTransport_new (arena, NULL);
  ASSERT_NOT_NULL (t);

  uint8_t ticket[(16 * 1024) + 1];
  memset (ticket, 0x42, sizeof (ticket));

  SocketQUICTransportParams_T saved;
  init_saved_peer_params (&saved);

  ASSERT_EQ (SocketQUICTransport_set_resumption_ticket (
                 t, ticket, sizeof (ticket), &saved, "h3", 2),
             -1);

  Arena_dispose (&arena);
}

TEST (quic_transport_set_resumption_ticket_rejects_alpn_mismatch)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICTransport_T t = SocketQUICTransport_new (arena, NULL);
  ASSERT_NOT_NULL (t);

  uint8_t ticket[32];
  memset (ticket, 0x33, sizeof (ticket));

  SocketQUICTransportParams_T saved;
  init_saved_peer_params (&saved);

  ASSERT_EQ (SocketQUICTransport_set_resumption_ticket (
                 t, ticket, sizeof (ticket), &saved, "nope", 4),
             -1);

  Arena_dispose (&arena);
}

TEST (quic_transport_set_resumption_ticket_accepts_valid)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICTransport_T t = SocketQUICTransport_new (arena, NULL);
  ASSERT_NOT_NULL (t);

  uint8_t ticket[32];
  memset (ticket, 0x55, sizeof (ticket));

  SocketQUICTransportParams_T saved;
  init_saved_peer_params (&saved);

  ASSERT_EQ (SocketQUICTransport_set_resumption_ticket (
                 t, ticket, sizeof (ticket), &saved, "h3", 2),
             0);

  SocketQUICTransport_close (t);
  Arena_dispose (&arena);
}

TEST (quic_transport_export_resumption_requires_connected)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICTransport_T t = SocketQUICTransport_new (arena, NULL);
  ASSERT_NOT_NULL (t);

  uint8_t ticket[256];
  size_t ticket_len = sizeof (ticket);

  SocketQUICTransportParams_T peer;
  char alpn[32];
  size_t alpn_len = sizeof (alpn);

  ASSERT_EQ (SocketQUICTransport_export_resumption (
                 t, ticket, &ticket_len, &peer, alpn, &alpn_len),
             -1);

  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

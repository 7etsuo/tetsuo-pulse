/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_stream_state.c - QUIC Stream State Machine tests (RFC 9000 Section
 * 3)
 *
 * Tests the dual state machines for sending and receiving parts of streams.
 * Each stream has independent send and receive state machines.
 */

#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "quic/SocketQUICStream.h"
#include "test/Test.h"

/* ============================================================================
 * Send State Machine Tests (RFC 9000 Section 3.1)
 * ============================================================================
 */

TEST (quic_stream_send_ready_to_send)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_READY);

  /* Ready -> Send on SEND_DATA */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_DATA);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_SEND);
}

TEST (quic_stream_send_ready_to_reset)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Ready -> ResetSent on SEND_RESET */
  SocketQUICStream_Result res = SocketQUICStream_transition_send (
      &stream, QUIC_STREAM_EVENT_SEND_RESET);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_RESET_SENT);
}

TEST (quic_stream_send_ready_stop_sending)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Ready -> ResetSent on RECV_STOP_SENDING */
  SocketQUICStream_Result res = SocketQUICStream_transition_send (
      &stream, QUIC_STREAM_EVENT_RECV_STOP_SENDING);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_RESET_SENT);
}

TEST (quic_stream_send_stay_in_send)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_SEND;

  /* Send -> Send on SEND_DATA (stay in state) */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_DATA);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_SEND);
}

TEST (quic_stream_send_to_data_sent)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_SEND;

  /* Send -> DataSent on SEND_FIN */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_FIN);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_DATA_SENT);
}

TEST (quic_stream_send_to_reset_from_send)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_SEND;

  /* Send -> ResetSent on SEND_RESET */
  SocketQUICStream_Result res = SocketQUICStream_transition_send (
      &stream, QUIC_STREAM_EVENT_SEND_RESET);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_RESET_SENT);
}

TEST (quic_stream_data_sent_to_data_recvd)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_DATA_SENT;

  /* DataSent -> DataRecvd on ALL_DATA_ACKED */
  SocketQUICStream_Result res = SocketQUICStream_transition_send (
      &stream, QUIC_STREAM_EVENT_ALL_DATA_ACKED);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_DATA_RECVD);
}

TEST (quic_stream_data_sent_to_reset)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_DATA_SENT;

  /* DataSent -> ResetSent on RECV_STOP_SENDING */
  SocketQUICStream_Result res = SocketQUICStream_transition_send (
      &stream, QUIC_STREAM_EVENT_RECV_STOP_SENDING);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_RESET_SENT);
}

TEST (quic_stream_reset_sent_to_reset_recvd)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_RESET_SENT;

  /* ResetSent -> ResetRecvd on RESET_ACKED */
  SocketQUICStream_Result res = SocketQUICStream_transition_send (
      &stream, QUIC_STREAM_EVENT_RESET_ACKED);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_RESET_RECVD);
}

TEST (quic_stream_send_terminal_data_recvd)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_DATA_RECVD;

  /* DataRecvd is terminal - no transitions allowed */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_DATA);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_STATE);
}

TEST (quic_stream_send_terminal_reset_recvd)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_RESET_RECVD;

  /* ResetRecvd is terminal - no transitions allowed */
  SocketQUICStream_Result res = SocketQUICStream_transition_send (
      &stream, QUIC_STREAM_EVENT_RESET_ACKED);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_STATE);
}

TEST (quic_stream_send_invalid_transition)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Invalid transition: Ready -> DataSent (must go through Send first) */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_FIN);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_STATE);
}

TEST (quic_stream_send_null_stream)
{
  SocketQUICStream_Result res
      = SocketQUICStream_transition_send (NULL, QUIC_STREAM_EVENT_SEND_DATA);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_NULL);
}

/* ============================================================================
 * Receive State Machine Tests (RFC 9000 Section 3.2)
 * ============================================================================
 */

TEST (quic_stream_recv_initial_state)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_RECV);
}

TEST (quic_stream_recv_stay_in_recv)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Recv -> Recv on RECV_DATA (stay in state) */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_DATA);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_RECV);
}

TEST (quic_stream_recv_to_size_known)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Recv -> SizeKnown on RECV_FIN */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_FIN);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_SIZE_KNOWN);
}

TEST (quic_stream_recv_to_reset_recvd)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Recv -> ResetRecvd on RECV_RESET */
  SocketQUICStream_Result res = SocketQUICStream_transition_recv (
      &stream, QUIC_STREAM_EVENT_RECV_RESET);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_RESET_RECVD);
}

TEST (quic_stream_size_known_stay)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.recv_state = QUIC_STREAM_STATE_SIZE_KNOWN;

  /* SizeKnown -> SizeKnown on RECV_DATA (stay in state) */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_DATA);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_SIZE_KNOWN);
}

TEST (quic_stream_size_known_to_data_recvd)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.recv_state = QUIC_STREAM_STATE_SIZE_KNOWN;

  /* SizeKnown -> DataRecvd on ALL_DATA_RECVD */
  SocketQUICStream_Result res = SocketQUICStream_transition_recv (
      &stream, QUIC_STREAM_EVENT_ALL_DATA_RECVD);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_DATA_RECVD);
}

TEST (quic_stream_size_known_to_reset)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.recv_state = QUIC_STREAM_STATE_SIZE_KNOWN;

  /* SizeKnown -> ResetRecvd on RECV_RESET */
  SocketQUICStream_Result res = SocketQUICStream_transition_recv (
      &stream, QUIC_STREAM_EVENT_RECV_RESET);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_RESET_RECVD);
}

TEST (quic_stream_data_recvd_to_data_read)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.recv_state = QUIC_STREAM_STATE_DATA_RECVD;

  /* DataRecvd -> DataRead on APP_READ_DATA */
  SocketQUICStream_Result res = SocketQUICStream_transition_recv (
      &stream, QUIC_STREAM_EVENT_APP_READ_DATA);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_DATA_READ);
}

TEST (quic_stream_reset_recvd_to_reset_read)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.recv_state = QUIC_STREAM_STATE_RESET_RECVD;

  /* ResetRecvd -> ResetRead on APP_READ_RESET */
  SocketQUICStream_Result res = SocketQUICStream_transition_recv (
      &stream, QUIC_STREAM_EVENT_APP_READ_RESET);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_RESET_READ);
}

TEST (quic_stream_recv_terminal_data_read)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.recv_state = QUIC_STREAM_STATE_DATA_READ;

  /* DataRead is terminal - no transitions allowed */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_DATA);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_STATE);
}

TEST (quic_stream_recv_terminal_reset_read)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.recv_state = QUIC_STREAM_STATE_RESET_READ;

  /* ResetRead is terminal - no transitions allowed */
  SocketQUICStream_Result res = SocketQUICStream_transition_recv (
      &stream, QUIC_STREAM_EVENT_APP_READ_RESET);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_STATE);
}

TEST (quic_stream_recv_invalid_transition)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Invalid transition: Recv -> DataRecvd (must go through SizeKnown) */
  SocketQUICStream_Result res = SocketQUICStream_transition_recv (
      &stream, QUIC_STREAM_EVENT_ALL_DATA_RECVD);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_STATE);
}

TEST (quic_stream_recv_null_stream)
{
  SocketQUICStream_Result res
      = SocketQUICStream_transition_recv (NULL, QUIC_STREAM_EVENT_RECV_DATA);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_NULL);
}

/* ============================================================================
 * Combined State Machine Tests
 * ============================================================================
 */

TEST (quic_stream_independent_state_machines)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Advance send state */
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_DATA);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_SEND);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_RECV); /* Unchanged */

  /* Advance recv state */
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_FIN);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_SEND); /* Unchanged */
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_SIZE_KNOWN);
}

TEST (quic_stream_normal_completion_flow)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Send side: Ready -> Send -> DataSent -> DataRecvd */
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_DATA);
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_FIN);
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_ALL_DATA_ACKED);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_DATA_RECVD);

  /* Receive side: Recv -> SizeKnown -> DataRecvd -> DataRead */
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_FIN);
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_ALL_DATA_RECVD);
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_APP_READ_DATA);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_DATA_READ);
}

TEST (quic_stream_reset_flow)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Send side: Ready -> Send -> ResetSent -> ResetRecvd */
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_DATA);
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_RESET);
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_RESET_ACKED);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_RESET_RECVD);

  /* Receive side: Recv -> ResetRecvd -> ResetRead */
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_RESET);
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_APP_READ_RESET);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_RESET_READ);
}

TEST (quic_stream_stop_sending_triggers_reset)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_SEND;

  /* STOP_SENDING from peer should trigger reset */
  SocketQUICStream_Result res = SocketQUICStream_transition_send (
      &stream, QUIC_STREAM_EVENT_RECV_STOP_SENDING);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_RESET_SENT);
}

/* ============================================================================
 * State Accessor Tests
 * ============================================================================
 */

TEST (quic_stream_get_send_state)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.send_state = QUIC_STREAM_STATE_SEND;

  ASSERT_EQ (SocketQUICStream_get_send_state (&stream), QUIC_STREAM_STATE_SEND);
}

TEST (quic_stream_get_send_state_null)
{
  ASSERT_EQ (SocketQUICStream_get_send_state (NULL), QUIC_STREAM_STATE_READY);
}

TEST (quic_stream_get_recv_state)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  stream.recv_state = QUIC_STREAM_STATE_SIZE_KNOWN;

  ASSERT_EQ (SocketQUICStream_get_recv_state (&stream),
             QUIC_STREAM_STATE_SIZE_KNOWN);
}

TEST (quic_stream_get_recv_state_null)
{
  ASSERT_EQ (SocketQUICStream_get_recv_state (NULL), QUIC_STREAM_STATE_RECV);
}

/* ============================================================================
 * Utility Function Tests
 * ============================================================================
 */

TEST (quic_stream_event_string)
{
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_SEND_DATA),
                  "SendData")
          == 0);
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_RECV_FIN),
                  "RecvFin")
          == 0);
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_RECV_RESET),
                  "RecvReset")
          == 0);
  ASSERT (strcmp (SocketQUICStream_event_string ((SocketQUICStreamEvent)999),
                  "Unknown")
          == 0);
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

TEST (quic_stream_multiple_data_sends)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Multiple SEND_DATA events should keep stream in Send state */
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_DATA);
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_DATA);
  SocketQUICStream_transition_send (&stream, QUIC_STREAM_EVENT_SEND_DATA);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_SEND);
}

TEST (quic_stream_multiple_data_receives)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Multiple RECV_DATA events should keep stream in Recv state */
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_DATA);
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_DATA);
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_DATA);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_RECV);
}

TEST (quic_stream_data_after_fin)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_FIN);

  /* Can still receive data in SizeKnown (filling gaps) */
  SocketQUICStream_Result res
      = SocketQUICStream_transition_recv (&stream, QUIC_STREAM_EVENT_RECV_DATA);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.recv_state, QUIC_STREAM_STATE_SIZE_KNOWN);
}

TEST (quic_stream_early_reset_from_ready)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);

  /* Can reset immediately from Ready without sending any data */
  SocketQUICStream_Result res = SocketQUICStream_transition_send (
      &stream, QUIC_STREAM_EVENT_SEND_RESET);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.send_state, QUIC_STREAM_STATE_RESET_SENT);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

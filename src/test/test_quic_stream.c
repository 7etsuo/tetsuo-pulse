/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_stream.c - QUIC Stream unit tests
 *
 * Tests stream ID encoding, type detection, stream lifecycle, and
 * edge cases for RFC 9000 Section 2 compliance.
 */

#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "quic/SocketQUICStream.h"
#include "test/Test.h"

/* ============================================================================
 * Stream ID Type Detection Tests (RFC 9000 Section 2.1)
 * ============================================================================
 */

TEST (quic_stream_type_bidi_client)
{
  /* Client-initiated bidirectional: 0x0, 0x4, 0x8, ... */
  ASSERT_EQ (SocketQUICStream_type (0x0), QUIC_STREAM_BIDI_CLIENT);
  ASSERT_EQ (SocketQUICStream_type (0x4), QUIC_STREAM_BIDI_CLIENT);
  ASSERT_EQ (SocketQUICStream_type (0x8), QUIC_STREAM_BIDI_CLIENT);
  ASSERT_EQ (SocketQUICStream_type (0x100), QUIC_STREAM_BIDI_CLIENT);
}

TEST (quic_stream_type_bidi_server)
{
  /* Server-initiated bidirectional: 0x1, 0x5, 0x9, ... */
  ASSERT_EQ (SocketQUICStream_type (0x1), QUIC_STREAM_BIDI_SERVER);
  ASSERT_EQ (SocketQUICStream_type (0x5), QUIC_STREAM_BIDI_SERVER);
  ASSERT_EQ (SocketQUICStream_type (0x9), QUIC_STREAM_BIDI_SERVER);
  ASSERT_EQ (SocketQUICStream_type (0x101), QUIC_STREAM_BIDI_SERVER);
}

TEST (quic_stream_type_uni_client)
{
  /* Client-initiated unidirectional: 0x2, 0x6, 0xA, ... */
  ASSERT_EQ (SocketQUICStream_type (0x2), QUIC_STREAM_UNI_CLIENT);
  ASSERT_EQ (SocketQUICStream_type (0x6), QUIC_STREAM_UNI_CLIENT);
  ASSERT_EQ (SocketQUICStream_type (0xA), QUIC_STREAM_UNI_CLIENT);
  ASSERT_EQ (SocketQUICStream_type (0x102), QUIC_STREAM_UNI_CLIENT);
}

TEST (quic_stream_type_uni_server)
{
  /* Server-initiated unidirectional: 0x3, 0x7, 0xB, ... */
  ASSERT_EQ (SocketQUICStream_type (0x3), QUIC_STREAM_UNI_SERVER);
  ASSERT_EQ (SocketQUICStream_type (0x7), QUIC_STREAM_UNI_SERVER);
  ASSERT_EQ (SocketQUICStream_type (0xB), QUIC_STREAM_UNI_SERVER);
  ASSERT_EQ (SocketQUICStream_type (0x103), QUIC_STREAM_UNI_SERVER);
}

/* ============================================================================
 * Stream Initiator Tests
 * ============================================================================
 */

TEST (quic_stream_is_client_initiated)
{
  /* Client-initiated: bit 0 = 0 */
  ASSERT (SocketQUICStream_is_client_initiated (0x0));
  ASSERT (SocketQUICStream_is_client_initiated (0x2));
  ASSERT (SocketQUICStream_is_client_initiated (0x4));
  ASSERT (SocketQUICStream_is_client_initiated (0x6));

  /* Server-initiated: bit 0 = 1 */
  ASSERT (!SocketQUICStream_is_client_initiated (0x1));
  ASSERT (!SocketQUICStream_is_client_initiated (0x3));
  ASSERT (!SocketQUICStream_is_client_initiated (0x5));
  ASSERT (!SocketQUICStream_is_client_initiated (0x7));
}

TEST (quic_stream_is_server_initiated)
{
  /* Server-initiated: bit 0 = 1 */
  ASSERT (SocketQUICStream_is_server_initiated (0x1));
  ASSERT (SocketQUICStream_is_server_initiated (0x3));
  ASSERT (SocketQUICStream_is_server_initiated (0x5));
  ASSERT (SocketQUICStream_is_server_initiated (0x7));

  /* Client-initiated: bit 0 = 0 */
  ASSERT (!SocketQUICStream_is_server_initiated (0x0));
  ASSERT (!SocketQUICStream_is_server_initiated (0x2));
  ASSERT (!SocketQUICStream_is_server_initiated (0x4));
  ASSERT (!SocketQUICStream_is_server_initiated (0x6));
}

/* ============================================================================
 * Stream Directionality Tests
 * ============================================================================
 */

TEST (quic_stream_is_bidirectional)
{
  /* Bidirectional: bit 1 = 0 */
  ASSERT (SocketQUICStream_is_bidirectional (0x0));
  ASSERT (SocketQUICStream_is_bidirectional (0x1));
  ASSERT (SocketQUICStream_is_bidirectional (0x4));
  ASSERT (SocketQUICStream_is_bidirectional (0x5));

  /* Unidirectional: bit 1 = 1 */
  ASSERT (!SocketQUICStream_is_bidirectional (0x2));
  ASSERT (!SocketQUICStream_is_bidirectional (0x3));
  ASSERT (!SocketQUICStream_is_bidirectional (0x6));
  ASSERT (!SocketQUICStream_is_bidirectional (0x7));
}

TEST (quic_stream_is_unidirectional)
{
  /* Unidirectional: bit 1 = 1 */
  ASSERT (SocketQUICStream_is_unidirectional (0x2));
  ASSERT (SocketQUICStream_is_unidirectional (0x3));
  ASSERT (SocketQUICStream_is_unidirectional (0x6));
  ASSERT (SocketQUICStream_is_unidirectional (0x7));

  /* Bidirectional: bit 1 = 0 */
  ASSERT (!SocketQUICStream_is_unidirectional (0x0));
  ASSERT (!SocketQUICStream_is_unidirectional (0x1));
  ASSERT (!SocketQUICStream_is_unidirectional (0x4));
  ASSERT (!SocketQUICStream_is_unidirectional (0x5));
}

/* ============================================================================
 * Stream ID Validation Tests
 * ============================================================================
 */

TEST (quic_stream_is_valid_id)
{
  /* Valid stream IDs */
  ASSERT (SocketQUICStream_is_valid_id (0));
  ASSERT (SocketQUICStream_is_valid_id (1));
  ASSERT (SocketQUICStream_is_valid_id (1000));
  ASSERT (SocketQUICStream_is_valid_id (QUIC_STREAM_ID_MAX));

  /* Invalid stream IDs (> 2^62-1) */
  ASSERT (!SocketQUICStream_is_valid_id (QUIC_STREAM_ID_MAX + 1));
  ASSERT (!SocketQUICStream_is_valid_id (UINT64_MAX));
}

/* ============================================================================
 * Stream ID Sequence Tests
 * ============================================================================
 */

TEST (quic_stream_first_id)
{
  ASSERT_EQ (SocketQUICStream_first_id (QUIC_STREAM_BIDI_CLIENT), 0);
  ASSERT_EQ (SocketQUICStream_first_id (QUIC_STREAM_BIDI_SERVER), 1);
  ASSERT_EQ (SocketQUICStream_first_id (QUIC_STREAM_UNI_CLIENT), 2);
  ASSERT_EQ (SocketQUICStream_first_id (QUIC_STREAM_UNI_SERVER), 3);
}

TEST (quic_stream_next_id)
{
  /* Client-initiated bidirectional: 0, 4, 8, 12, ... */
  ASSERT_EQ (SocketQUICStream_next_id (0), 4);
  ASSERT_EQ (SocketQUICStream_next_id (4), 8);
  ASSERT_EQ (SocketQUICStream_next_id (8), 12);

  /* Server-initiated bidirectional: 1, 5, 9, 13, ... */
  ASSERT_EQ (SocketQUICStream_next_id (1), 5);
  ASSERT_EQ (SocketQUICStream_next_id (5), 9);

  /* Client-initiated unidirectional: 2, 6, 10, 14, ... */
  ASSERT_EQ (SocketQUICStream_next_id (2), 6);
  ASSERT_EQ (SocketQUICStream_next_id (6), 10);

  /* Server-initiated unidirectional: 3, 7, 11, 15, ... */
  ASSERT_EQ (SocketQUICStream_next_id (3), 7);
  ASSERT_EQ (SocketQUICStream_next_id (7), 11);
}

TEST (quic_stream_next_id_overflow)
{
  /* Near maximum - should still work */
  uint64_t near_max = QUIC_STREAM_ID_MAX - 4;
  uint64_t next = SocketQUICStream_next_id (near_max);

  /* Depends on the last 2 bits of near_max; check validity */
  if (next != 0)
    {
      ASSERT (SocketQUICStream_is_valid_id (next));
    }

  /* At maximum - should return 0 (overflow) */
  ASSERT_EQ (SocketQUICStream_next_id (QUIC_STREAM_ID_MAX), 0);
  ASSERT_EQ (SocketQUICStream_next_id (QUIC_STREAM_ID_MAX - 1), 0);
  ASSERT_EQ (SocketQUICStream_next_id (QUIC_STREAM_ID_MAX - 2), 0);
  ASSERT_EQ (SocketQUICStream_next_id (QUIC_STREAM_ID_MAX - 3), 0);
}

TEST (quic_stream_sequence)
{
  /* Stream sequence = stream_id / 4 */
  ASSERT_EQ (SocketQUICStream_sequence (0), 0);
  ASSERT_EQ (SocketQUICStream_sequence (1), 0);
  ASSERT_EQ (SocketQUICStream_sequence (2), 0);
  ASSERT_EQ (SocketQUICStream_sequence (3), 0);

  ASSERT_EQ (SocketQUICStream_sequence (4), 1);
  ASSERT_EQ (SocketQUICStream_sequence (5), 1);
  ASSERT_EQ (SocketQUICStream_sequence (6), 1);
  ASSERT_EQ (SocketQUICStream_sequence (7), 1);

  ASSERT_EQ (SocketQUICStream_sequence (8), 2);
  ASSERT_EQ (SocketQUICStream_sequence (100), 25);
  ASSERT_EQ (SocketQUICStream_sequence (1000), 250);
}

/* ============================================================================
 * Stream Creation Tests
 * ============================================================================
 */

TEST (quic_stream_new_bidi_client)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICStream_T stream = SocketQUICStream_new (arena, 0);
  ASSERT_NOT_NULL (stream);

  ASSERT_EQ (SocketQUICStream_get_id (stream), 0);
  ASSERT_EQ (SocketQUICStream_get_type (stream), QUIC_STREAM_BIDI_CLIENT);
  ASSERT_EQ (SocketQUICStream_get_state (stream), QUIC_STREAM_STATE_READY);

  Arena_dispose (&arena);
}

TEST (quic_stream_new_uni_server)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICStream_T stream = SocketQUICStream_new (arena, 3);
  ASSERT_NOT_NULL (stream);

  ASSERT_EQ (SocketQUICStream_get_id (stream), 3);
  ASSERT_EQ (SocketQUICStream_get_type (stream), QUIC_STREAM_UNI_SERVER);

  Arena_dispose (&arena);
}

TEST (quic_stream_new_large_id)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Large valid stream ID */
  uint64_t large_id = 1000000004; /* Type: client bidi */
  SocketQUICStream_T stream = SocketQUICStream_new (arena, large_id);
  ASSERT_NOT_NULL (stream);

  ASSERT_EQ (SocketQUICStream_get_id (stream), large_id);
  ASSERT_EQ (SocketQUICStream_get_type (stream), QUIC_STREAM_BIDI_CLIENT);

  Arena_dispose (&arena);
}

TEST (quic_stream_new_null_arena)
{
  SocketQUICStream_T stream = SocketQUICStream_new (NULL, 0);
  ASSERT_NULL (stream);
}

TEST (quic_stream_new_invalid_id)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Invalid stream ID (exceeds maximum) */
  SocketQUICStream_T stream
      = SocketQUICStream_new (arena, QUIC_STREAM_ID_MAX + 1);
  ASSERT_NULL (stream);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Stream Init/Reset Tests
 * ============================================================================
 */

TEST (quic_stream_init)
{
  struct SocketQUICStream stream;

  SocketQUICStream_Result res = SocketQUICStream_init (&stream, 5);
  ASSERT_EQ (res, QUIC_STREAM_OK);
  ASSERT_EQ (stream.id, 5);
  ASSERT_EQ (stream.type, QUIC_STREAM_BIDI_SERVER);
  ASSERT_EQ (stream.state, QUIC_STREAM_STATE_READY);
}

TEST (quic_stream_init_null)
{
  SocketQUICStream_Result res = SocketQUICStream_init (NULL, 0);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_NULL);
}

TEST (quic_stream_init_invalid_id)
{
  struct SocketQUICStream stream;

  SocketQUICStream_Result res
      = SocketQUICStream_init (&stream, QUIC_STREAM_ID_MAX + 1);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_INVALID_ID);
}

TEST (quic_stream_reset)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 6);
  stream.data_sent = 1000;
  stream.fin_sent = 1;

  SocketQUICStream_Result res = SocketQUICStream_reset (&stream);
  ASSERT_EQ (res, QUIC_STREAM_OK);

  /* ID and type should be preserved */
  ASSERT_EQ (stream.id, 6);
  ASSERT_EQ (stream.type, QUIC_STREAM_UNI_CLIENT);

  /* Other fields should be reset */
  ASSERT_EQ (stream.data_sent, 0);
  ASSERT_EQ (stream.fin_sent, 0);
  ASSERT_EQ (stream.state, QUIC_STREAM_STATE_READY);
}

TEST (quic_stream_reset_null)
{
  SocketQUICStream_Result res = SocketQUICStream_reset (NULL);
  ASSERT_EQ (res, QUIC_STREAM_ERROR_NULL);
}

/* ============================================================================
 * Stream Access Function Tests
 * ============================================================================
 */

TEST (quic_stream_get_id_null)
{
  ASSERT_EQ (SocketQUICStream_get_id (NULL), 0);
}

TEST (quic_stream_get_type_null)
{
  ASSERT_EQ (SocketQUICStream_get_type (NULL), QUIC_STREAM_BIDI_CLIENT);
}

TEST (quic_stream_get_state_null)
{
  ASSERT_EQ (SocketQUICStream_get_state (NULL), QUIC_STREAM_STATE_READY);
}

TEST (quic_stream_get_send_state_null)
{
  ASSERT_EQ (SocketQUICStream_get_send_state (NULL), QUIC_STREAM_STATE_READY);
}

TEST (quic_stream_get_recv_state_null)
{
  ASSERT_EQ (SocketQUICStream_get_recv_state (NULL), QUIC_STREAM_STATE_RECV);
}

TEST (quic_stream_get_send_state)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  ASSERT_EQ (SocketQUICStream_get_send_state (&stream),
             QUIC_STREAM_STATE_READY);

  stream.send_state = QUIC_STREAM_STATE_SEND;
  ASSERT_EQ (SocketQUICStream_get_send_state (&stream), QUIC_STREAM_STATE_SEND);

  stream.send_state = QUIC_STREAM_STATE_DATA_SENT;
  ASSERT_EQ (SocketQUICStream_get_send_state (&stream),
             QUIC_STREAM_STATE_DATA_SENT);
}

TEST (quic_stream_get_recv_state)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  ASSERT_EQ (SocketQUICStream_get_recv_state (&stream), QUIC_STREAM_STATE_RECV);

  stream.recv_state = QUIC_STREAM_STATE_SIZE_KNOWN;
  ASSERT_EQ (SocketQUICStream_get_recv_state (&stream),
             QUIC_STREAM_STATE_SIZE_KNOWN);

  stream.recv_state = QUIC_STREAM_STATE_DATA_READ;
  ASSERT_EQ (SocketQUICStream_get_recv_state (&stream),
             QUIC_STREAM_STATE_DATA_READ);
}

TEST (quic_stream_is_local_null)
{
  ASSERT_EQ (SocketQUICStream_is_local (NULL), 0);
}

TEST (quic_stream_is_local)
{
  struct SocketQUICStream stream;

  SocketQUICStream_init (&stream, 0);
  ASSERT_EQ (SocketQUICStream_is_local (&stream), 0);

  stream.is_local = 1;
  ASSERT_EQ (SocketQUICStream_is_local (&stream), 1);
}

/* ============================================================================
 * String Utility Tests
 * ============================================================================
 */

TEST (quic_stream_type_string)
{
  ASSERT (strcmp (SocketQUICStream_type_string (QUIC_STREAM_BIDI_CLIENT),
                  "Client-Initiated Bidirectional")
          == 0);
  ASSERT (strcmp (SocketQUICStream_type_string (QUIC_STREAM_BIDI_SERVER),
                  "Server-Initiated Bidirectional")
          == 0);
  ASSERT (strcmp (SocketQUICStream_type_string (QUIC_STREAM_UNI_CLIENT),
                  "Client-Initiated Unidirectional")
          == 0);
  ASSERT (strcmp (SocketQUICStream_type_string (QUIC_STREAM_UNI_SERVER),
                  "Server-Initiated Unidirectional")
          == 0);
  ASSERT (strcmp (SocketQUICStream_type_string ((SocketQUICStreamType)99),
                  "Unknown")
          == 0);
}

TEST (quic_stream_state_string)
{
  ASSERT (
      strcmp (SocketQUICStream_state_string (QUIC_STREAM_STATE_READY), "Ready")
      == 0);
  ASSERT (
      strcmp (SocketQUICStream_state_string (QUIC_STREAM_STATE_SEND), "Send")
      == 0);
  ASSERT (
      strcmp (SocketQUICStream_state_string (QUIC_STREAM_STATE_RECV), "Recv")
      == 0);
  ASSERT (strcmp (SocketQUICStream_state_string ((SocketQUICStreamState)99),
                  "Unknown")
          == 0);
}

TEST (quic_stream_result_string)
{
  ASSERT (strcmp (SocketQUICStream_result_string (QUIC_STREAM_OK), "OK") == 0);
  ASSERT (strcmp (SocketQUICStream_result_string (QUIC_STREAM_ERROR_NULL),
                  "NULL pointer argument")
          == 0);
  ASSERT (strcmp (SocketQUICStream_result_string ((SocketQUICStream_Result)99),
                  "Unknown error")
          == 0);
}

TEST (quic_stream_event_string)
{
  /* Send-side events */
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_SEND_DATA),
                  "SendData")
          == 0);
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_SEND_FIN),
                  "SendFin")
          == 0);
  ASSERT (
      strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_ALL_DATA_ACKED),
              "AllDataAcked")
      == 0);
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_SEND_RESET),
                  "SendReset")
          == 0);
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_RESET_ACKED),
                  "ResetAcked")
          == 0);

  /* Receive-side events */
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_RECV_DATA),
                  "RecvData")
          == 0);
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_RECV_FIN),
                  "RecvFin")
          == 0);
  ASSERT (
      strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_ALL_DATA_RECVD),
              "AllDataRecvd")
      == 0);
  ASSERT (
      strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_APP_READ_DATA),
              "AppReadData")
      == 0);
  ASSERT (strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_RECV_RESET),
                  "RecvReset")
          == 0);
  ASSERT (
      strcmp (SocketQUICStream_event_string (QUIC_STREAM_EVENT_APP_READ_RESET),
              "AppReadReset")
      == 0);

  /* Bidirectional events */
  ASSERT (strcmp (SocketQUICStream_event_string (
                      QUIC_STREAM_EVENT_RECV_STOP_SENDING),
                  "RecvStopSending")
          == 0);

  /* Invalid event */
  ASSERT (strcmp (SocketQUICStream_event_string ((SocketQUICStreamEvent)99),
                  "Unknown")
          == 0);
}

/* ============================================================================
 * Combined Type and Sequence Tests
 * ============================================================================
 */

TEST (quic_stream_type_sequence_combined)
{
  /* Verify that types repeat every 4 IDs */
  for (uint64_t i = 0; i < 100; i += 4)
    {
      ASSERT_EQ (SocketQUICStream_type (i), QUIC_STREAM_BIDI_CLIENT);
      ASSERT_EQ (SocketQUICStream_type (i + 1), QUIC_STREAM_BIDI_SERVER);
      ASSERT_EQ (SocketQUICStream_type (i + 2), QUIC_STREAM_UNI_CLIENT);
      ASSERT_EQ (SocketQUICStream_type (i + 3), QUIC_STREAM_UNI_SERVER);
    }
}

TEST (quic_stream_large_sequence)
{
  /* Test with large stream IDs */
  uint64_t large_id = 0x1000000000ULL; /* 2^36 */

  ASSERT (SocketQUICStream_is_valid_id (large_id));
  ASSERT_EQ (SocketQUICStream_type (large_id), QUIC_STREAM_BIDI_CLIENT);
  ASSERT_EQ (SocketQUICStream_sequence (large_id), large_id >> 2);
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

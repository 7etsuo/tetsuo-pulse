/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICStream-state.c
 * @brief QUIC Stream State Machines (RFC 9000 Section 3).
 *
 * Implements dual state machines for sending and receiving parts of streams.
 * Each stream has independent send and receive state machines that track
 * the lifecycle of data flow in each direction.
 *
 * Send States (RFC 9000 Section 3.1):
 *   Ready -> Send -> DataSent -> DataRecvd (normal flow)
 *   Ready/Send/DataSent -> ResetSent -> ResetRecvd (reset flow)
 *
 * Receive States (RFC 9000 Section 3.2):
 *   Recv -> SizeKnown -> DataRecvd -> DataRead (normal flow)
 *   Recv/SizeKnown -> ResetRecvd -> ResetRead (reset flow)
 */

#include "quic/SocketQUICStream.h"

#include <assert.h>
#include <stddef.h>

/* ============================================================================
 * Event String Table
 * ============================================================================
 */

static const char *event_strings[] = {
  [QUIC_STREAM_EVENT_SEND_DATA] = "SendData",
  [QUIC_STREAM_EVENT_SEND_FIN] = "SendFin",
  [QUIC_STREAM_EVENT_ALL_DATA_ACKED] = "AllDataAcked",
  [QUIC_STREAM_EVENT_SEND_RESET] = "SendReset",
  [QUIC_STREAM_EVENT_RESET_ACKED] = "ResetAcked",
  [QUIC_STREAM_EVENT_RECV_DATA] = "RecvData",
  [QUIC_STREAM_EVENT_RECV_FIN] = "RecvFin",
  [QUIC_STREAM_EVENT_ALL_DATA_RECVD] = "AllDataRecvd",
  [QUIC_STREAM_EVENT_APP_READ_DATA] = "AppReadData",
  [QUIC_STREAM_EVENT_RECV_RESET] = "RecvReset",
  [QUIC_STREAM_EVENT_APP_READ_RESET] = "AppReadReset",
  [QUIC_STREAM_EVENT_RECV_STOP_SENDING] = "RecvStopSending"
};

const char *
SocketQUICStream_event_string (SocketQUICStreamEvent event)
{
  if (event > QUIC_STREAM_EVENT_RECV_STOP_SENDING)
    return "Unknown";
  return event_strings[event];
}

/* ============================================================================
 * State Accessor Functions
 * ============================================================================
 */

SocketQUICStreamState
SocketQUICStream_get_send_state (const SocketQUICStream_T stream)
{
  if (stream == NULL)
    return QUIC_STREAM_STATE_READY;
  return stream->send_state;
}

SocketQUICStreamState
SocketQUICStream_get_recv_state (const SocketQUICStream_T stream)
{
  if (stream == NULL)
    return QUIC_STREAM_STATE_RECV;
  return stream->recv_state;
}

/* ============================================================================
 * Send-Side State Machine (RFC 9000 Section 3.1)
 * ============================================================================
 */

/**
 * @brief Validate and execute send-side state transition.
 *
 * State transition table:
 *
 *   Ready:
 *     - SEND_DATA -> Send
 *     - SEND_RESET -> ResetSent
 *     - RECV_STOP_SENDING -> ResetSent
 *
 *   Send:
 *     - SEND_DATA -> Send (stay in state)
 *     - SEND_FIN -> DataSent
 *     - SEND_RESET -> ResetSent
 *     - RECV_STOP_SENDING -> ResetSent
 *
 *   DataSent:
 *     - ALL_DATA_ACKED -> DataRecvd (terminal)
 *     - SEND_RESET -> ResetSent
 *     - RECV_STOP_SENDING -> ResetSent
 *
 *   ResetSent:
 *     - RESET_ACKED -> ResetRecvd (terminal)
 *
 *   DataRecvd: Terminal state (no transitions)
 *   ResetRecvd: Terminal state (no transitions)
 */
SocketQUICStream_Result
SocketQUICStream_transition_send (SocketQUICStream_T stream,
                                  SocketQUICStreamEvent event)
{
  SocketQUICStreamState current;
  SocketQUICStreamState next;

  if (stream == NULL)
    return QUIC_STREAM_ERROR_NULL;

  current = stream->send_state;

  /* Terminal states */
  if (current == QUIC_STREAM_STATE_DATA_RECVD
      || current == QUIC_STREAM_STATE_RESET_RECVD)
    {
      return QUIC_STREAM_ERROR_STATE; /* No transitions from terminal states */
    }

  /* State transition logic */
  switch (current)
    {
    case QUIC_STREAM_STATE_READY:
      if (event == QUIC_STREAM_EVENT_SEND_DATA)
        next = QUIC_STREAM_STATE_SEND;
      else if (event == QUIC_STREAM_EVENT_SEND_RESET
               || event == QUIC_STREAM_EVENT_RECV_STOP_SENDING)
        next = QUIC_STREAM_STATE_RESET_SENT;
      else
        return QUIC_STREAM_ERROR_STATE;
      break;

    case QUIC_STREAM_STATE_SEND:
      if (event == QUIC_STREAM_EVENT_SEND_DATA)
        next = QUIC_STREAM_STATE_SEND; /* Stay in Send */
      else if (event == QUIC_STREAM_EVENT_SEND_FIN)
        next = QUIC_STREAM_STATE_DATA_SENT;
      else if (event == QUIC_STREAM_EVENT_SEND_RESET
               || event == QUIC_STREAM_EVENT_RECV_STOP_SENDING)
        next = QUIC_STREAM_STATE_RESET_SENT;
      else
        return QUIC_STREAM_ERROR_STATE;
      break;

    case QUIC_STREAM_STATE_DATA_SENT:
      if (event == QUIC_STREAM_EVENT_ALL_DATA_ACKED)
        next = QUIC_STREAM_STATE_DATA_RECVD;
      else if (event == QUIC_STREAM_EVENT_SEND_RESET
               || event == QUIC_STREAM_EVENT_RECV_STOP_SENDING)
        next = QUIC_STREAM_STATE_RESET_SENT;
      else
        return QUIC_STREAM_ERROR_STATE;
      break;

    case QUIC_STREAM_STATE_RESET_SENT:
      if (event == QUIC_STREAM_EVENT_RESET_ACKED)
        next = QUIC_STREAM_STATE_RESET_RECVD;
      else
        return QUIC_STREAM_ERROR_STATE;
      break;

    default:
      return QUIC_STREAM_ERROR_STATE; /* Invalid state */
    }

  /* Execute transition */
  stream->send_state = next;

  /* Update legacy combined state for backwards compatibility */
  if (stream->send_state == QUIC_STREAM_STATE_SEND
      || stream->send_state == QUIC_STREAM_STATE_DATA_SENT)
    stream->state = stream->send_state;

  return QUIC_STREAM_OK;
}

/* ============================================================================
 * Receive-Side State Machine (RFC 9000 Section 3.2)
 * ============================================================================
 */

/**
 * @brief State transition entry for receive-side state machine.
 */
typedef struct
{
  SocketQUICStreamState from_state;
  SocketQUICStreamEvent event;
  SocketQUICStreamState to_state;
} RecvStateTransition;

/**
 * @brief Receive-side state transition table (RFC 9000 Section 3.2).
 *
 * Encodes all valid state transitions for the receive side of a QUIC stream:
 *
 *   Recv -> Recv (on RECV_DATA)
 *   Recv -> SizeKnown (on RECV_FIN)
 *   Recv -> ResetRecvd (on RECV_RESET)
 *   SizeKnown -> SizeKnown (on RECV_DATA)
 *   SizeKnown -> DataRecvd (on ALL_DATA_RECVD)
 *   SizeKnown -> ResetRecvd (on RECV_RESET)
 *   DataRecvd -> DataRead (on APP_READ_DATA, terminal)
 *   ResetRecvd -> ResetRead (on APP_READ_RESET, terminal)
 */
static const RecvStateTransition recv_transitions[] = {
  {QUIC_STREAM_STATE_RECV, QUIC_STREAM_EVENT_RECV_DATA,
   QUIC_STREAM_STATE_RECV},
  {QUIC_STREAM_STATE_RECV, QUIC_STREAM_EVENT_RECV_FIN,
   QUIC_STREAM_STATE_SIZE_KNOWN},
  {QUIC_STREAM_STATE_RECV, QUIC_STREAM_EVENT_RECV_RESET,
   QUIC_STREAM_STATE_RESET_RECVD},

  {QUIC_STREAM_STATE_SIZE_KNOWN, QUIC_STREAM_EVENT_RECV_DATA,
   QUIC_STREAM_STATE_SIZE_KNOWN},
  {QUIC_STREAM_STATE_SIZE_KNOWN, QUIC_STREAM_EVENT_ALL_DATA_RECVD,
   QUIC_STREAM_STATE_DATA_RECVD},
  {QUIC_STREAM_STATE_SIZE_KNOWN, QUIC_STREAM_EVENT_RECV_RESET,
   QUIC_STREAM_STATE_RESET_RECVD},

  {QUIC_STREAM_STATE_DATA_RECVD, QUIC_STREAM_EVENT_APP_READ_DATA,
   QUIC_STREAM_STATE_DATA_READ},

  {QUIC_STREAM_STATE_RESET_RECVD, QUIC_STREAM_EVENT_APP_READ_RESET,
   QUIC_STREAM_STATE_RESET_READ}
};

#define RECV_TRANSITIONS_COUNT                                                \
  (sizeof (recv_transitions) / sizeof (recv_transitions[0]))

/**
 * @brief Validate and execute receive-side state transition.
 *
 * Uses table-driven lookup to find valid transitions from current state
 * given an event. Terminal states (DataRead, ResetRead) are checked
 * before table lookup.
 */
SocketQUICStream_Result
SocketQUICStream_transition_recv (SocketQUICStream_T stream,
                                  SocketQUICStreamEvent event)
{
  SocketQUICStreamState current;

  if (stream == NULL)
    return QUIC_STREAM_ERROR_NULL;

  current = stream->recv_state;

  /* Terminal states */
  if (current == QUIC_STREAM_STATE_DATA_READ
      || current == QUIC_STREAM_STATE_RESET_READ)
    {
      return QUIC_STREAM_ERROR_STATE;
    }

  /* Table-driven transition lookup */
  for (size_t i = 0; i < RECV_TRANSITIONS_COUNT; i++)
    {
      if (recv_transitions[i].from_state == current
          && recv_transitions[i].event == event)
        {
          stream->recv_state = recv_transitions[i].to_state;

          /* Update legacy combined state for backwards compatibility */
          if (stream->recv_state == QUIC_STREAM_STATE_RECV
              || stream->recv_state == QUIC_STREAM_STATE_SIZE_KNOWN)
            stream->state = stream->recv_state;

          return QUIC_STREAM_OK;
        }
    }

  return QUIC_STREAM_ERROR_STATE; /* No valid transition found */
}

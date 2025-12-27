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
  if (event < 0 || event > QUIC_STREAM_EVENT_RECV_STOP_SENDING)
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
 * @brief Validate and execute receive-side state transition.
 *
 * State transition table:
 *
 *   Recv:
 *     - RECV_DATA -> Recv (stay in state)
 *     - RECV_FIN -> SizeKnown
 *     - RECV_RESET -> ResetRecvd
 *
 *   SizeKnown:
 *     - RECV_DATA -> SizeKnown (stay in state)
 *     - ALL_DATA_RECVD -> DataRecvd
 *     - RECV_RESET -> ResetRecvd
 *
 *   DataRecvd:
 *     - APP_READ_DATA -> DataRead (terminal)
 *
 *   ResetRecvd:
 *     - APP_READ_RESET -> ResetRead (terminal)
 *
 *   DataRead: Terminal state (no transitions)
 *   ResetRead: Terminal state (no transitions)
 */
SocketQUICStream_Result
SocketQUICStream_transition_recv (SocketQUICStream_T stream,
                                  SocketQUICStreamEvent event)
{
  SocketQUICStreamState current;
  SocketQUICStreamState next;

  if (stream == NULL)
    return QUIC_STREAM_ERROR_NULL;

  current = stream->recv_state;

  /* Terminal states */
  if (current == QUIC_STREAM_STATE_DATA_READ
      || current == QUIC_STREAM_STATE_RESET_READ)
    {
      return QUIC_STREAM_ERROR_STATE; /* No transitions from terminal states */
    }

  /* State transition logic */
  switch (current)
    {
    case QUIC_STREAM_STATE_RECV:
      if (event == QUIC_STREAM_EVENT_RECV_DATA)
        next = QUIC_STREAM_STATE_RECV; /* Stay in Recv */
      else if (event == QUIC_STREAM_EVENT_RECV_FIN)
        next = QUIC_STREAM_STATE_SIZE_KNOWN;
      else if (event == QUIC_STREAM_EVENT_RECV_RESET)
        next = QUIC_STREAM_STATE_RESET_RECVD;
      else
        return QUIC_STREAM_ERROR_STATE;
      break;

    case QUIC_STREAM_STATE_SIZE_KNOWN:
      if (event == QUIC_STREAM_EVENT_RECV_DATA)
        next = QUIC_STREAM_STATE_SIZE_KNOWN; /* Stay in SizeKnown */
      else if (event == QUIC_STREAM_EVENT_ALL_DATA_RECVD)
        next = QUIC_STREAM_STATE_DATA_RECVD;
      else if (event == QUIC_STREAM_EVENT_RECV_RESET)
        next = QUIC_STREAM_STATE_RESET_RECVD;
      else
        return QUIC_STREAM_ERROR_STATE;
      break;

    case QUIC_STREAM_STATE_DATA_RECVD:
      if (event == QUIC_STREAM_EVENT_APP_READ_DATA)
        next = QUIC_STREAM_STATE_DATA_READ;
      else
        return QUIC_STREAM_ERROR_STATE;
      break;

    case QUIC_STREAM_STATE_RESET_RECVD:
      if (event == QUIC_STREAM_EVENT_APP_READ_RESET)
        next = QUIC_STREAM_STATE_RESET_READ;
      else
        return QUIC_STREAM_ERROR_STATE;
      break;

    default:
      return QUIC_STREAM_ERROR_STATE; /* Invalid state */
    }

  /* Execute transition */
  stream->recv_state = next;

  /* Update legacy combined state for backwards compatibility */
  if (stream->recv_state == QUIC_STREAM_STATE_RECV
      || stream->recv_state == QUIC_STREAM_STATE_SIZE_KNOWN)
    stream->state = stream->recv_state;

  return QUIC_STREAM_OK;
}

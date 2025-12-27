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
 * @brief State transition table entry.
 *
 * Defines a single valid state transition: from_state + event -> to_state.
 */
typedef struct
{
  SocketQUICStreamState from_state; /**< Source state */
  SocketQUICStreamEvent event;      /**< Triggering event */
  SocketQUICStreamState to_state;   /**< Destination state */
} StateTransition;

/**
 * @brief Send-side state transition table (RFC 9000 Section 3.1).
 *
 * This table defines all valid state transitions for the sending part
 * of a QUIC stream. Each entry represents: (from_state, event) -> to_state.
 *
 * Valid transitions:
 *   Ready -> Send (on SEND_DATA)
 *   Ready -> ResetSent (on SEND_RESET or RECV_STOP_SENDING)
 *   Send -> Send (on SEND_DATA, stay in state)
 *   Send -> DataSent (on SEND_FIN)
 *   Send -> ResetSent (on SEND_RESET or RECV_STOP_SENDING)
 *   DataSent -> DataRecvd (on ALL_DATA_ACKED, terminal)
 *   DataSent -> ResetSent (on SEND_RESET or RECV_STOP_SENDING)
 *   ResetSent -> ResetRecvd (on RESET_ACKED, terminal)
 *
 * Terminal states (DataRecvd, ResetRecvd) have no transitions.
 */
static const StateTransition send_transitions[] = {
  /* From Ready */
  { QUIC_STREAM_STATE_READY, QUIC_STREAM_EVENT_SEND_DATA,
    QUIC_STREAM_STATE_SEND },
  { QUIC_STREAM_STATE_READY, QUIC_STREAM_EVENT_SEND_RESET,
    QUIC_STREAM_STATE_RESET_SENT },
  { QUIC_STREAM_STATE_READY, QUIC_STREAM_EVENT_RECV_STOP_SENDING,
    QUIC_STREAM_STATE_RESET_SENT },

  /* From Send */
  { QUIC_STREAM_STATE_SEND, QUIC_STREAM_EVENT_SEND_DATA,
    QUIC_STREAM_STATE_SEND }, /* Stay in Send */
  { QUIC_STREAM_STATE_SEND, QUIC_STREAM_EVENT_SEND_FIN,
    QUIC_STREAM_STATE_DATA_SENT },
  { QUIC_STREAM_STATE_SEND, QUIC_STREAM_EVENT_SEND_RESET,
    QUIC_STREAM_STATE_RESET_SENT },
  { QUIC_STREAM_STATE_SEND, QUIC_STREAM_EVENT_RECV_STOP_SENDING,
    QUIC_STREAM_STATE_RESET_SENT },

  /* From DataSent */
  { QUIC_STREAM_STATE_DATA_SENT, QUIC_STREAM_EVENT_ALL_DATA_ACKED,
    QUIC_STREAM_STATE_DATA_RECVD },
  { QUIC_STREAM_STATE_DATA_SENT, QUIC_STREAM_EVENT_SEND_RESET,
    QUIC_STREAM_STATE_RESET_SENT },
  { QUIC_STREAM_STATE_DATA_SENT, QUIC_STREAM_EVENT_RECV_STOP_SENDING,
    QUIC_STREAM_STATE_RESET_SENT },

  /* From ResetSent */
  { QUIC_STREAM_STATE_RESET_SENT, QUIC_STREAM_EVENT_RESET_ACKED,
    QUIC_STREAM_STATE_RESET_RECVD }
};

#define SEND_TRANSITIONS_COUNT                                                \
  (sizeof (send_transitions) / sizeof (send_transitions[0]))

/**
 * @brief Validate and execute send-side state transition.
 *
 * Uses a table-driven approach for clarity and maintainability.
 * All valid transitions are defined in the send_transitions[] table.
 *
 * Terminal states (DataRecvd, ResetRecvd) have no valid transitions.
 *
 * @param stream Stream to transition.
 * @param event  Event triggering the transition.
 *
 * @return QUIC_STREAM_OK on success, error code otherwise.
 */
SocketQUICStream_Result
SocketQUICStream_transition_send (SocketQUICStream_T stream,
                                  SocketQUICStreamEvent event)
{
  SocketQUICStreamState current;
  size_t i;

  if (stream == NULL)
    return QUIC_STREAM_ERROR_NULL;

  current = stream->send_state;

  /* Terminal states have no valid transitions */
  if (current == QUIC_STREAM_STATE_DATA_RECVD
      || current == QUIC_STREAM_STATE_RESET_RECVD)
    {
      return QUIC_STREAM_ERROR_STATE;
    }

  /* Search transition table for valid transition */
  for (i = 0; i < SEND_TRANSITIONS_COUNT; i++)
    {
      if (send_transitions[i].from_state == current
          && send_transitions[i].event == event)
        {
          /* Valid transition found - execute it */
          stream->send_state = send_transitions[i].to_state;

          /* Update legacy combined state for backwards compatibility */
          if (stream->send_state == QUIC_STREAM_STATE_SEND
              || stream->send_state == QUIC_STREAM_STATE_DATA_SENT)
            stream->state = stream->send_state;

          return QUIC_STREAM_OK;
        }
    }

  /* No valid transition found */
  return QUIC_STREAM_ERROR_STATE;
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

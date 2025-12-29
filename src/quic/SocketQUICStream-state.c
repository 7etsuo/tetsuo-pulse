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
  if (event < 0 || event > QUIC_STREAM_EVENT_MAX)
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
 * Legacy State Update Helpers
 * ============================================================================
 */

/**
 * @brief Update legacy combined state based on send state.
 *
 * For backwards compatibility, maintains the legacy `stream->state` field
 * by mirroring send-side states (Send, DataSent).
 *
 * @param stream Stream to update.
 */
static void
update_legacy_state_send (SocketQUICStream_T stream)
{
  if (stream->send_state == QUIC_STREAM_STATE_SEND
      || stream->send_state == QUIC_STREAM_STATE_DATA_SENT)
    stream->state = stream->send_state;
}

/**
 * @brief Update legacy combined state based on receive state.
 *
 * For backwards compatibility, maintains the legacy `stream->state` field
 * by mirroring receive-side states (Recv, SizeKnown).
 *
 * @param stream Stream to update.
 */
static void
update_legacy_state_recv (SocketQUICStream_T stream)
{
  if (stream->recv_state == QUIC_STREAM_STATE_RECV
      || stream->recv_state == QUIC_STREAM_STATE_SIZE_KNOWN)
    stream->state = stream->recv_state;
}

/* ============================================================================
 * Send-Side State Machine (RFC 9000 Section 3.1)
 * ============================================================================
 */

/**
 * @brief State transition table entry.
 *
 * Defines a single valid state transition: from_state + event -> to_state.
 * Used by both send-side and receive-side state machines.
 */
typedef struct
{
  SocketQUICStreamState from_state; /**< Source state */
  SocketQUICStreamEvent event;      /**< Triggering event */
  SocketQUICStreamState to_state;   /**< Destination state */
} SocketQUICStreamTransition;

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
static const SocketQUICStreamTransition send_transitions[] = {
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
  for (size_t i = 0; i < SEND_TRANSITIONS_COUNT; i++)
    {
      /* Skip non-matching transitions */
      if (send_transitions[i].from_state != current ||
          send_transitions[i].event != event)
        continue;

      /* Valid transition found - execute it */
      stream->send_state = send_transitions[i].to_state;

      /* Update flags based on transition */
      if (event == QUIC_STREAM_EVENT_SEND_FIN)
        stream->fin_sent = 1;
      else if (event == QUIC_STREAM_EVENT_SEND_RESET ||
               event == QUIC_STREAM_EVENT_RECV_STOP_SENDING)
        stream->reset_sent = 1;

      /* Update legacy combined state for backwards compatibility */
      update_legacy_state_send (stream);

      return QUIC_STREAM_OK;
    }

  /* No valid transition found */
  return QUIC_STREAM_ERROR_STATE;
}

/* ============================================================================
 * Receive-Side State Machine (RFC 9000 Section 3.2)
 * ============================================================================
 */

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
static const SocketQUICStreamTransition recv_transitions[] = {
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
      /* Skip non-matching transitions */
      if (recv_transitions[i].from_state != current ||
          recv_transitions[i].event != event)
        continue;

      stream->recv_state = recv_transitions[i].to_state;

      /* Update flags based on transition */
      if (event == QUIC_STREAM_EVENT_RECV_FIN)
        stream->fin_received = 1;
      else if (event == QUIC_STREAM_EVENT_RECV_RESET)
        stream->reset_received = 1;

      /* Update legacy combined state for backwards compatibility */
      update_legacy_state_recv (stream);

      return QUIC_STREAM_OK;
    }

  return QUIC_STREAM_ERROR_STATE; /* No valid transition found */
}

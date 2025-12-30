/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICStream.c - QUIC Stream Management (RFC 9000 Section 2)
 *
 * Implements stream ID encoding/decoding, type detection, and basic
 * stream lifecycle management for QUIC multiplexed streams.
 */

#include <assert.h>
#include <string.h>

#include "quic/SocketQUICStream.h"
#include "quic/SocketQUICConstants.h"

/* ============================================================================
 * String Tables
 * ============================================================================
 */

static const char *type_strings[] = {
  [QUIC_STREAM_BIDI_CLIENT] = "Client-Initiated Bidirectional",
  [QUIC_STREAM_BIDI_SERVER] = "Server-Initiated Bidirectional",
  [QUIC_STREAM_UNI_CLIENT] = "Client-Initiated Unidirectional",
  [QUIC_STREAM_UNI_SERVER] = "Server-Initiated Unidirectional"
};

static const char *state_strings[] = {
  [QUIC_STREAM_STATE_READY] = "Ready",
  [QUIC_STREAM_STATE_SEND] = "Send",
  [QUIC_STREAM_STATE_DATA_SENT] = "DataSent",
  [QUIC_STREAM_STATE_RESET_SENT] = "ResetSent",
  [QUIC_STREAM_STATE_DATA_RECVD] = "DataRecvd",
  [QUIC_STREAM_STATE_RESET_RECVD] = "ResetRecvd",
  [QUIC_STREAM_STATE_RECV] = "Recv",
  [QUIC_STREAM_STATE_SIZE_KNOWN] = "SizeKnown",
  [QUIC_STREAM_STATE_DATA_READ] = "DataRead",
  [QUIC_STREAM_STATE_RESET_READ] = "ResetRead"
};

static const char *result_strings[] = {
  [QUIC_STREAM_OK] = "OK",
  [QUIC_STREAM_ERROR_NULL] = "NULL pointer argument",
  [QUIC_STREAM_ERROR_INVALID_ID] = "Stream ID exceeds maximum",
  [QUIC_STREAM_ERROR_INVALID_TYPE] = "Invalid stream type",
  [QUIC_STREAM_ERROR_WRONG_ROLE] = "Wrong role for stream operation",
  [QUIC_STREAM_ERROR_STATE] = "Invalid state transition",
  [QUIC_STREAM_ERROR_LIMIT] = "Stream limit exceeded"
};

static const char *event_strings[] = {
  [QUIC_STREAM_EVENT_SEND_DATA] = "Send Data",
  [QUIC_STREAM_EVENT_SEND_FIN] = "Send FIN",
  [QUIC_STREAM_EVENT_ALL_DATA_ACKED] = "All Data Acked",
  [QUIC_STREAM_EVENT_SEND_RESET] = "Send Reset",
  [QUIC_STREAM_EVENT_RESET_ACKED] = "Reset Acked",
  [QUIC_STREAM_EVENT_RECV_DATA] = "Receive Data",
  [QUIC_STREAM_EVENT_RECV_FIN] = "Receive FIN",
  [QUIC_STREAM_EVENT_ALL_DATA_RECVD] = "All Data Received",
  [QUIC_STREAM_EVENT_APP_READ_DATA] = "App Read Data",
  [QUIC_STREAM_EVENT_RECV_RESET] = "Receive Reset",
  [QUIC_STREAM_EVENT_APP_READ_RESET] = "App Read Reset",
  [QUIC_STREAM_EVENT_RECV_STOP_SENDING] = "Receive Stop Sending"
};

/* ============================================================================
 * Stream ID Functions (RFC 9000 Section 2.1)
 * ============================================================================
 */

int
SocketQUICStream_is_client_initiated (uint64_t stream_id)
{
  return (stream_id & QUIC_STREAM_INITIATOR_MASK) == 0;
}

int
SocketQUICStream_is_server_initiated (uint64_t stream_id)
{
  return (stream_id & QUIC_STREAM_INITIATOR_MASK) != 0;
}

int
SocketQUICStream_is_bidirectional (uint64_t stream_id)
{
  return (stream_id & QUIC_STREAM_DIRECTION_MASK) == 0;
}

int
SocketQUICStream_is_unidirectional (uint64_t stream_id)
{
  return (stream_id & QUIC_STREAM_DIRECTION_MASK) != 0;
}

SocketQUICStreamType
SocketQUICStream_type (uint64_t stream_id)
{
  return (SocketQUICStreamType)(stream_id & QUIC_STREAM_TYPE_MASK);
}

int
SocketQUICStream_is_valid_id (uint64_t stream_id)
{
  return stream_id <= QUIC_STREAM_ID_MAX;
}

uint64_t
SocketQUICStream_next_id (uint64_t stream_id)
{
  uint64_t next = stream_id + QUIC_STREAM_ID_INCREMENT;

  /* Check for overflow */
  if (next > QUIC_STREAM_ID_MAX || next < stream_id)
    return 0;

  return next;
}

uint64_t
SocketQUICStream_first_id (SocketQUICStreamType type)
{
  return (uint64_t)type;
}

uint64_t
SocketQUICStream_sequence (uint64_t stream_id)
{
  return stream_id >> QUIC_STREAM_TYPE_BITS;
}

/* ============================================================================
 * Stream Lifecycle Functions
 * ============================================================================
 */

/**
 * stream_set_defaults - Initialize stream fields to default values
 * @stream: Stream structure to initialize
 * @stream_id: Stream ID to assign
 *
 * Sets the stream's ID, type, and initial states. Should be called after
 * memset() to zero the structure.
 */
static void
stream_set_defaults (SocketQUICStream_T stream, uint64_t stream_id)
{
  stream->id = stream_id;
  stream->type = SocketQUICStream_type (stream_id);
  stream->state = QUIC_STREAM_STATE_READY; /* Legacy */
  stream->send_state = QUIC_STREAM_STATE_READY;
  stream->recv_state = QUIC_STREAM_STATE_RECV;
}

SocketQUICStream_T
SocketQUICStream_new (Arena_T arena, uint64_t stream_id)
{
  SocketQUICStream_T stream;

  if (arena == NULL)
    return NULL;

  if (!SocketQUICStream_is_valid_id (stream_id))
    return NULL;

  stream = Arena_alloc (arena, sizeof (*stream), __FILE__, __LINE__);
  if (stream == NULL)
    return NULL;

  if (SocketQUICStream_init (stream, stream_id) != QUIC_STREAM_OK)
    return NULL;

  return stream;
}

SocketQUICStream_Result
SocketQUICStream_init (SocketQUICStream_T stream, uint64_t stream_id)
{
  if (stream == NULL)
    return QUIC_STREAM_ERROR_NULL;

  if (!SocketQUICStream_is_valid_id (stream_id))
    return QUIC_STREAM_ERROR_INVALID_ID;

  memset (stream, 0, sizeof (*stream));
  stream_set_defaults (stream, stream_id);

  return QUIC_STREAM_OK;
}

SocketQUICStream_Result
SocketQUICStream_reset (SocketQUICStream_T stream)
{
  uint64_t id;

  if (stream == NULL)
    return QUIC_STREAM_ERROR_NULL;

  id = stream->id;
  memset (stream, 0, sizeof (*stream));
  stream_set_defaults (stream, id);

  return QUIC_STREAM_OK;
}

/* ============================================================================
 * Stream Access Functions
 * ============================================================================
 */

uint64_t
SocketQUICStream_get_id (const SocketQUICStream_T stream)
{
  if (stream == NULL)
    return 0;
  return stream->id;
}

SocketQUICStreamType
SocketQUICStream_get_type (const SocketQUICStream_T stream)
{
  if (stream == NULL)
    return QUIC_STREAM_BIDI_CLIENT;
  return stream->type;
}

SocketQUICStreamState
SocketQUICStream_get_state (const SocketQUICStream_T stream)
{
  if (stream == NULL)
    return QUIC_STREAM_STATE_READY;
  return stream->state;
}

int
SocketQUICStream_is_local (const SocketQUICStream_T stream)
{
  if (stream == NULL)
    return 0;
  return stream->is_local;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

const char *
SocketQUICStream_type_string (SocketQUICStreamType type)
{
  if (type > QUIC_STREAM_UNI_SERVER)
    return "Unknown";
  return type_strings[type];
}

const char *
SocketQUICStream_state_string (SocketQUICStreamState state)
{
  if (state > QUIC_STREAM_STATE_RESET_READ)
    return "Unknown";
  return state_strings[state];
}

/* Note: SocketQUICStream_event_string is in SocketQUICStream-state.c */

DEFINE_RESULT_STRING_FUNC (SocketQUICStream, QUIC_STREAM_ERROR_LIMIT)

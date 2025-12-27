/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFlow.c
 * @brief QUIC Flow Control Implementation (RFC 9000 Section 4).
 */

#include "quic/SocketQUICFlow.h"

#include <assert.h>
#include <string.h>

/* ============================================================================
 * Connection-Level Flow Control
 * ============================================================================
 */

SocketQUICFlow_T
SocketQUICFlow_new (Arena_T arena)
{
  SocketQUICFlow_T fc;

  if (!arena)
    return NULL;

  fc = Arena_alloc (arena, sizeof (*fc), __FILE__, __LINE__);
  if (!fc)
    return NULL;

  memset (fc, 0, sizeof (*fc));

  /* Initialize with default values */
  fc->recv_max_data = QUIC_FLOW_DEFAULT_CONN_WINDOW;
  fc->send_max_data = QUIC_FLOW_DEFAULT_CONN_WINDOW;
  fc->max_streams_bidi = QUIC_FLOW_DEFAULT_MAX_STREAMS_BIDI;
  fc->max_streams_uni = QUIC_FLOW_DEFAULT_MAX_STREAMS_UNI;

  return fc;
}

SocketQUICFlow_Result
SocketQUICFlow_init (SocketQUICFlow_T fc, uint64_t recv_max_data,
                     uint64_t send_max_data, uint64_t max_streams_bidi,
                     uint64_t max_streams_uni)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  if (recv_max_data > QUIC_FLOW_MAX_WINDOW
      || send_max_data > QUIC_FLOW_MAX_WINDOW)
    return QUIC_FLOW_ERROR_OVERFLOW;

  memset (fc, 0, sizeof (*fc));

  fc->recv_max_data = recv_max_data;
  fc->send_max_data = send_max_data;
  fc->max_streams_bidi = max_streams_bidi;
  fc->max_streams_uni = max_streams_uni;

  return QUIC_FLOW_OK;
}

int
SocketQUICFlow_can_send (const SocketQUICFlow_T fc, size_t bytes)
{
  if (!fc)
    return 0;

  /* Check if adding bytes would exceed send_max_data */
  if (bytes > UINT64_MAX - fc->send_consumed)
    return 0; /* Would overflow */

  return (fc->send_consumed + bytes) <= fc->send_max_data;
}

SocketQUICFlow_Result
SocketQUICFlow_consume_send (SocketQUICFlow_T fc, size_t bytes)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  /* Check for overflow */
  if (bytes > UINT64_MAX - fc->send_consumed)
    return QUIC_FLOW_ERROR_OVERFLOW;

  uint64_t new_consumed = fc->send_consumed + bytes;

  /* Check flow control limit */
  if (new_consumed > fc->send_max_data)
    return QUIC_FLOW_ERROR_BLOCKED;

  fc->send_consumed = new_consumed;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlow_consume_recv (SocketQUICFlow_T fc, size_t bytes)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  /* Check for overflow */
  if (bytes > UINT64_MAX - fc->recv_consumed)
    return QUIC_FLOW_ERROR_OVERFLOW;

  uint64_t new_consumed = fc->recv_consumed + bytes;

  /* Check flow control limit */
  if (new_consumed > fc->recv_max_data)
    return QUIC_FLOW_ERROR_BLOCKED;

  fc->recv_consumed = new_consumed;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlow_update_send_max (SocketQUICFlow_T fc, uint64_t max_data)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  if (max_data > QUIC_FLOW_MAX_WINDOW)
    return QUIC_FLOW_ERROR_OVERFLOW;

  /* MAX_DATA frames must not decrease the limit (RFC 9000 §4.1) */
  if (max_data < fc->send_max_data)
    return QUIC_FLOW_ERROR_INVALID;

  fc->send_max_data = max_data;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlow_update_recv_max (SocketQUICFlow_T fc, uint64_t max_data)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  if (max_data > QUIC_FLOW_MAX_WINDOW)
    return QUIC_FLOW_ERROR_OVERFLOW;

  fc->recv_max_data = max_data;
  return QUIC_FLOW_OK;
}

uint64_t
SocketQUICFlow_send_window (const SocketQUICFlow_T fc)
{
  if (!fc)
    return 0;

  if (fc->send_consumed >= fc->send_max_data)
    return 0;

  return fc->send_max_data - fc->send_consumed;
}

uint64_t
SocketQUICFlow_recv_window (const SocketQUICFlow_T fc)
{
  if (!fc)
    return 0;

  if (fc->recv_consumed >= fc->recv_max_data)
    return 0;

  return fc->recv_max_data - fc->recv_consumed;
}

/* ============================================================================
 * Stream-Level Flow Control
 * ============================================================================
 */

SocketQUICFlowStream_T
SocketQUICFlowStream_new (Arena_T arena, uint64_t stream_id)
{
  SocketQUICFlowStream_T fs;

  if (!arena)
    return NULL;

  fs = Arena_alloc (arena, sizeof (*fs), __FILE__, __LINE__);
  if (!fs)
    return NULL;

  memset (fs, 0, sizeof (*fs));

  fs->stream_id = stream_id;
  fs->recv_max_data = QUIC_FLOW_DEFAULT_STREAM_WINDOW;
  fs->send_max_data = QUIC_FLOW_DEFAULT_STREAM_WINDOW;

  return fs;
}

SocketQUICFlow_Result
SocketQUICFlowStream_init (SocketQUICFlowStream_T fs, uint64_t stream_id,
                           uint64_t recv_max_data, uint64_t send_max_data)
{
  if (!fs)
    return QUIC_FLOW_ERROR_NULL;

  if (recv_max_data > QUIC_FLOW_MAX_WINDOW
      || send_max_data > QUIC_FLOW_MAX_WINDOW)
    return QUIC_FLOW_ERROR_OVERFLOW;

  memset (fs, 0, sizeof (*fs));

  fs->stream_id = stream_id;
  fs->recv_max_data = recv_max_data;
  fs->send_max_data = send_max_data;

  return QUIC_FLOW_OK;
}

int
SocketQUICFlowStream_can_send (const SocketQUICFlowStream_T fs, size_t bytes)
{
  if (!fs)
    return 0;

  /* Check if adding bytes would exceed send_max_data */
  if (bytes > UINT64_MAX - fs->send_consumed)
    return 0; /* Would overflow */

  return (fs->send_consumed + bytes) <= fs->send_max_data;
}

SocketQUICFlow_Result
SocketQUICFlowStream_consume_send (SocketQUICFlowStream_T fs, size_t bytes)
{
  if (!fs)
    return QUIC_FLOW_ERROR_NULL;

  /* Check for overflow */
  if (bytes > UINT64_MAX - fs->send_consumed)
    return QUIC_FLOW_ERROR_OVERFLOW;

  uint64_t new_consumed = fs->send_consumed + bytes;

  /* Check flow control limit */
  if (new_consumed > fs->send_max_data)
    return QUIC_FLOW_ERROR_BLOCKED;

  fs->send_consumed = new_consumed;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlowStream_consume_recv (SocketQUICFlowStream_T fs, size_t bytes)
{
  if (!fs)
    return QUIC_FLOW_ERROR_NULL;

  /* Check for overflow */
  if (bytes > UINT64_MAX - fs->recv_consumed)
    return QUIC_FLOW_ERROR_OVERFLOW;

  uint64_t new_consumed = fs->recv_consumed + bytes;

  /* Check flow control limit */
  if (new_consumed > fs->recv_max_data)
    return QUIC_FLOW_ERROR_BLOCKED;

  fs->recv_consumed = new_consumed;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlowStream_update_send_max (SocketQUICFlowStream_T fs,
                                      uint64_t max_data)
{
  if (!fs)
    return QUIC_FLOW_ERROR_NULL;

  if (max_data > QUIC_FLOW_MAX_WINDOW)
    return QUIC_FLOW_ERROR_OVERFLOW;

  /* MAX_STREAM_DATA must not decrease the limit (RFC 9000 §4.1) */
  if (max_data < fs->send_max_data)
    return QUIC_FLOW_ERROR_INVALID;

  fs->send_max_data = max_data;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlowStream_update_recv_max (SocketQUICFlowStream_T fs,
                                      uint64_t max_data)
{
  if (!fs)
    return QUIC_FLOW_ERROR_NULL;

  if (max_data > QUIC_FLOW_MAX_WINDOW)
    return QUIC_FLOW_ERROR_OVERFLOW;

  fs->recv_max_data = max_data;
  return QUIC_FLOW_OK;
}

uint64_t
SocketQUICFlowStream_send_window (const SocketQUICFlowStream_T fs)
{
  if (!fs)
    return 0;

  if (fs->send_consumed >= fs->send_max_data)
    return 0;

  return fs->send_max_data - fs->send_consumed;
}

uint64_t
SocketQUICFlowStream_recv_window (const SocketQUICFlowStream_T fs)
{
  if (!fs)
    return 0;

  if (fs->recv_consumed >= fs->recv_max_data)
    return 0;

  return fs->recv_max_data - fs->recv_consumed;
}

/* ============================================================================
 * Stream Count Management
 * ============================================================================
 */

SocketQUICFlow_Result
SocketQUICFlow_update_max_streams_bidi (SocketQUICFlow_T fc,
                                        uint64_t max_streams)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  if (max_streams > QUIC_FLOW_MAX_WINDOW)
    return QUIC_FLOW_ERROR_OVERFLOW;

  /* MAX_STREAMS must not decrease the limit (RFC 9000 §4.6) */
  if (max_streams < fc->max_streams_bidi)
    return QUIC_FLOW_ERROR_INVALID;

  fc->max_streams_bidi = max_streams;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlow_update_max_streams_uni (SocketQUICFlow_T fc,
                                       uint64_t max_streams)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  if (max_streams > QUIC_FLOW_MAX_WINDOW)
    return QUIC_FLOW_ERROR_OVERFLOW;

  /* MAX_STREAMS must not decrease the limit (RFC 9000 §4.6) */
  if (max_streams < fc->max_streams_uni)
    return QUIC_FLOW_ERROR_INVALID;

  fc->max_streams_uni = max_streams;
  return QUIC_FLOW_OK;
}

int
SocketQUICFlow_can_open_stream_bidi (const SocketQUICFlow_T fc)
{
  if (!fc)
    return 0;

  return fc->streams_bidi_count < fc->max_streams_bidi;
}

int
SocketQUICFlow_can_open_stream_uni (const SocketQUICFlow_T fc)
{
  if (!fc)
    return 0;

  return fc->streams_uni_count < fc->max_streams_uni;
}

SocketQUICFlow_Result
SocketQUICFlow_open_stream_bidi (SocketQUICFlow_T fc)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  if (fc->streams_bidi_count >= fc->max_streams_bidi)
    return QUIC_FLOW_ERROR_BLOCKED;

  fc->streams_bidi_count++;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlow_open_stream_uni (SocketQUICFlow_T fc)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  if (fc->streams_uni_count >= fc->max_streams_uni)
    return QUIC_FLOW_ERROR_BLOCKED;

  fc->streams_uni_count++;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlow_close_stream_bidi (SocketQUICFlow_T fc)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  if (fc->streams_bidi_count == 0)
    return QUIC_FLOW_ERROR_INVALID;

  fc->streams_bidi_count--;
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlow_close_stream_uni (SocketQUICFlow_T fc)
{
  if (!fc)
    return QUIC_FLOW_ERROR_NULL;

  if (fc->streams_uni_count == 0)
    return QUIC_FLOW_ERROR_INVALID;

  fc->streams_uni_count--;
  return QUIC_FLOW_OK;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

const char *
SocketQUICFlow_result_string (SocketQUICFlow_Result result)
{
  switch (result)
    {
    case QUIC_FLOW_OK:
      return "QUIC_FLOW_OK";
    case QUIC_FLOW_ERROR_NULL:
      return "QUIC_FLOW_ERROR_NULL";
    case QUIC_FLOW_ERROR_BLOCKED:
      return "QUIC_FLOW_ERROR_BLOCKED";
    case QUIC_FLOW_ERROR_OVERFLOW:
      return "QUIC_FLOW_ERROR_OVERFLOW";
    case QUIC_FLOW_ERROR_INVALID:
      return "QUIC_FLOW_ERROR_INVALID";
    default:
      return "UNKNOWN";
    }
}

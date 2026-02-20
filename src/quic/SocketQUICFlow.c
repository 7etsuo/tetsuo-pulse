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
#include "quic/SocketQUICConstants.h"

#include <assert.h>
#include <string.h>

/**
 * @brief Helper macro for consume_send flow control logic.
 *
 * Eliminates duplication between connection-level and stream-level
 * consume_send functions. Validates pointer, checks for overflow,
 * and enforces flow control limits.
 *
 * @param ptr Pointer to flow control structure (fc or fs)
 * @param consumed_field Name of consumed counter field
 * @param max_field Name of maximum data field
 * @param bytes Number of bytes to consume
 * @return Returns early with appropriate error code on failure
 */
#define CONSUME_FLOW_SEND(ptr, consumed_field, max_field, bytes) \
  do                                                             \
    {                                                            \
      if (!(ptr))                                                \
        return QUIC_FLOW_ERROR_NULL;                             \
      if ((bytes) > UINT64_MAX - (ptr)->consumed_field)          \
        return QUIC_FLOW_ERROR_OVERFLOW;                         \
      uint64_t new_consumed = (ptr)->consumed_field + (bytes);   \
      if (new_consumed > (ptr)->max_field)                       \
        return QUIC_FLOW_ERROR_BLOCKED;                          \
      (ptr)->consumed_field = new_consumed;                      \
    }                                                            \
  while (0)

/**
 * @brief Helper macro to consume received bytes with overflow and bounds
 * checking.
 *
 * This macro eliminates code duplication between connection-level and
 * stream-level flow control consume_recv functions. It performs:
 * 1. NULL pointer check
 * 2. Overflow detection (addition would exceed UINT64_MAX)
 * 3. Flow control bounds check (new_consumed <= max_field)
 * 4. Updates consumed field if checks pass
 *
 * @param ptr Pointer to flow control structure (fc or fs)
 * @param consumed_field Name of the consumed bytes field (recv_consumed)
 * @param max_field Name of the maximum data field (recv_max_data)
 * @param bytes Number of bytes to consume
 *
 * @note Caller must return QUIC_FLOW_OK after macro succeeds.
 * @note Macro returns error codes directly on failure.
 */
#define CONSUME_FLOW_RECV(ptr, consumed_field, max_field, bytes) \
  do                                                             \
    {                                                            \
      if (!(ptr))                                                \
        return QUIC_FLOW_ERROR_NULL;                             \
      if ((bytes) > UINT64_MAX - (ptr)->consumed_field)          \
        return QUIC_FLOW_ERROR_OVERFLOW;                         \
      uint64_t new_consumed = (ptr)->consumed_field + (bytes);   \
      if (new_consumed > (ptr)->max_field)                       \
        return QUIC_FLOW_ERROR_BLOCKED;                          \
      (ptr)->consumed_field = new_consumed;                      \
    }                                                            \
  while (0)

/**
 * @brief Check if bytes can be sent without exceeding flow control limits.
 *
 * @param ptr Pointer to flow control structure (connection or stream level)
 * @param consumed_field Name of the consumed bytes field
 * @param max_field Name of the max bytes field
 * @param bytes Number of bytes to check
 * @return 1 if bytes can be sent, 0 otherwise
 */
#define CAN_SEND_FLOW(ptr, consumed_field, max_field, bytes) \
  (!(ptr) ? 0                                                \
   : ((bytes) > UINT64_MAX - (ptr)->consumed_field)          \
       ? 0                                                   \
       : ((ptr)->consumed_field + (bytes)) <= (ptr)->max_field)

/**
 * @brief Calculate available flow control window.
 *
 * This macro implements the common window calculation pattern used by both
 * connection-level and stream-level flow control functions. It returns 0
 * if the pointer is NULL or if consumed >= max, otherwise returns the
 * difference (max - consumed).
 *
 * @param ptr Pointer to flow control structure (connection or stream)
 * @param consumed_field Name of the consumed bytes field
 * @param max_field Name of the maximum bytes field
 * @return Available window in bytes, or 0 if blocked/invalid
 */
#define GET_FLOW_WINDOW(ptr, consumed_field, max_field) \
  (!(ptr) ? 0                                           \
   : ((ptr)->consumed_field >= (ptr)->max_field)        \
       ? 0                                              \
       : ((ptr)->max_field - (ptr)->consumed_field))

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
SocketQUICFlow_init (SocketQUICFlow_T fc,
                     uint64_t recv_max_data,
                     uint64_t send_max_data,
                     uint64_t max_streams_bidi,
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
  return CAN_SEND_FLOW (fc, send_consumed, send_max_data, bytes);
}

SocketQUICFlow_Result
SocketQUICFlow_consume_send (SocketQUICFlow_T fc, size_t bytes)
{
  CONSUME_FLOW_SEND (fc, send_consumed, send_max_data, bytes);
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlow_consume_recv (SocketQUICFlow_T fc, size_t bytes)
{
  CONSUME_FLOW_RECV (fc, recv_consumed, recv_max_data, bytes);
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
  return GET_FLOW_WINDOW (fc, send_consumed, send_max_data);
}

uint64_t
SocketQUICFlow_recv_window (const SocketQUICFlow_T fc)
{
  return GET_FLOW_WINDOW (fc, recv_consumed, recv_max_data);
}

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
SocketQUICFlowStream_init (SocketQUICFlowStream_T fs,
                           uint64_t stream_id,
                           uint64_t recv_max_data,
                           uint64_t send_max_data)
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
  return CAN_SEND_FLOW (fs, send_consumed, send_max_data, bytes);
}

SocketQUICFlow_Result
SocketQUICFlowStream_consume_send (SocketQUICFlowStream_T fs, size_t bytes)
{
  CONSUME_FLOW_SEND (fs, send_consumed, send_max_data, bytes);
  return QUIC_FLOW_OK;
}

SocketQUICFlow_Result
SocketQUICFlowStream_consume_recv (SocketQUICFlowStream_T fs, size_t bytes)
{
  CONSUME_FLOW_RECV (fs, recv_consumed, recv_max_data, bytes);
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
  return GET_FLOW_WINDOW (fs, send_consumed, send_max_data);
}

uint64_t
SocketQUICFlowStream_recv_window (const SocketQUICFlowStream_T fs)
{
  return GET_FLOW_WINDOW (fs, recv_consumed, recv_max_data);
}

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

static const char *result_strings[] = {
  [QUIC_FLOW_OK] = "QUIC_FLOW_OK",
  [QUIC_FLOW_ERROR_NULL] = "QUIC_FLOW_ERROR_NULL",
  [QUIC_FLOW_ERROR_BLOCKED] = "QUIC_FLOW_ERROR_BLOCKED",
  [QUIC_FLOW_ERROR_OVERFLOW] = "QUIC_FLOW_ERROR_OVERFLOW",
  [QUIC_FLOW_ERROR_INVALID] = "QUIC_FLOW_ERROR_INVALID",
};

DEFINE_RESULT_STRING_FUNC (SocketQUICFlow, QUIC_FLOW_ERROR_INVALID)

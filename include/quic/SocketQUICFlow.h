/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFlow.h
 * @brief QUIC Flow Control (RFC 9000 Section 4).
 *
 * Implements credit-based flow control at connection and stream levels.
 *
 * Flow control prevents receivers from being overwhelmed by data:
 * - Connection-level: MAX_DATA limits total bytes across all streams
 * - Stream-level: MAX_STREAM_DATA per individual stream
 * - Stream count: MAX_STREAMS limits concurrent streams
 * - BLOCKED frames signal when limits prevent sending
 *
 * Thread Safety: Flow control structures are not thread-safe.
 * Use external synchronization when sharing across threads.
 *
 * @defgroup quic_flow QUIC Flow Control Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-4
 */

#ifndef SOCKETQUICFLOW_INCLUDED
#define SOCKETQUICFLOW_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

/**
 * @brief Default initial connection-level flow control window (1 MB).
 */
#define QUIC_FLOW_DEFAULT_CONN_WINDOW (1024 * 1024)

/**
 * @brief Default initial stream-level flow control window (256 KB).
 */
#define QUIC_FLOW_DEFAULT_STREAM_WINDOW (256 * 1024)

/**
 * @brief Default maximum concurrent bidirectional streams.
 */
#define QUIC_FLOW_DEFAULT_MAX_STREAMS_BIDI 100

/**
 * @brief Default maximum concurrent unidirectional streams.
 */
#define QUIC_FLOW_DEFAULT_MAX_STREAMS_UNI 100

/**
 * @brief Maximum allowed flow control window size (2^62 - 1).
 *
 * Per RFC 9000, flow control values are encoded as QUIC variable-length
 * integers, which have a maximum value of 2^62 - 1.
 */
#define QUIC_FLOW_MAX_WINDOW ((uint64_t)4611686018427387903ULL)

/**
 * @brief Result codes for flow control operations.
 */
typedef enum
{
  QUIC_FLOW_OK = 0,         /**< Operation succeeded */
  QUIC_FLOW_ERROR_NULL,     /**< NULL pointer argument */
  QUIC_FLOW_ERROR_BLOCKED,  /**< Flow control window exhausted */
  QUIC_FLOW_ERROR_OVERFLOW, /**< Value would exceed maximum */
  QUIC_FLOW_ERROR_INVALID   /**< Invalid parameter value */
} SocketQUICFlow_Result;

/**
 * @brief Connection-level flow control state.
 *
 * Tracks flow control windows for the entire connection, limiting
 * total bytes across all streams.
 */
struct SocketQUICFlowControl
{
  /* Send direction (data we send to peer) */
  uint64_t send_max_data; /**< Peer's advertised MAX_DATA limit */
  uint64_t send_consumed; /**< Total bytes sent so far */

  /* Receive direction (data peer sends to us) */
  uint64_t recv_max_data; /**< Our advertised MAX_DATA limit */
  uint64_t recv_consumed; /**< Total bytes received so far */

  /* Stream limits */
  uint64_t max_streams_bidi;   /**< Max concurrent bidirectional streams */
  uint64_t max_streams_uni;    /**< Max concurrent unidirectional streams */
  uint64_t streams_bidi_count; /**< Current bidirectional stream count */
  uint64_t streams_uni_count;  /**< Current unidirectional stream count */
};

/**
 * @brief Stream-level flow control state.
 *
 * Tracks flow control windows for an individual stream.
 */
struct SocketQUICFlowStream
{
  uint64_t stream_id; /**< Stream ID this flow control applies to */

  /* Send direction */
  uint64_t send_max_data; /**< Peer's MAX_STREAM_DATA limit */
  uint64_t send_consumed; /**< Bytes sent on this stream */

  /* Receive direction */
  uint64_t recv_max_data; /**< Our MAX_STREAM_DATA limit */
  uint64_t recv_consumed; /**< Bytes received on this stream */
};

/**
 * @brief Opaque flow control handle (connection-level).
 */
typedef struct SocketQUICFlowControl *SocketQUICFlow_T;

/**
 * @brief Opaque stream flow control handle.
 */
typedef struct SocketQUICFlowStream *SocketQUICFlowStream_T;

/**
 * @brief Create a new connection-level flow control state.
 *
 * Initializes flow control with default window sizes.
 *
 * @param arena Memory arena for allocation.
 *
 * @return New flow control handle, or NULL on allocation failure.
 */
extern SocketQUICFlow_T SocketQUICFlow_new (Arena_T arena);

/**
 * @brief Initialize flow control with custom window sizes.
 *
 * @param fc             Flow control structure to initialize.
 * @param recv_max_data  Our initial MAX_DATA limit.
 * @param send_max_data  Peer's initial MAX_DATA limit.
 * @param max_streams_bidi Max bidirectional streams.
 * @param max_streams_uni  Max unidirectional streams.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result SocketQUICFlow_init (SocketQUICFlow_T fc,
                                                  uint64_t recv_max_data,
                                                  uint64_t send_max_data,
                                                  uint64_t max_streams_bidi,
                                                  uint64_t max_streams_uni);

/**
 * @brief Check if we can send data within connection flow control limits.
 *
 * @param fc    Flow control handle.
 * @param bytes Number of bytes to send.
 *
 * @return 1 if send is allowed, 0 if blocked by flow control.
 */
extern int SocketQUICFlow_can_send (const SocketQUICFlow_T fc, size_t bytes);

/**
 * @brief Consume send window (data sent to peer).
 *
 * Updates bytes_sent counter. Must check SocketQUICFlow_can_send first.
 *
 * @param fc    Flow control handle.
 * @param bytes Number of bytes consumed.
 *
 * @return QUIC_FLOW_OK on success, QUIC_FLOW_ERROR_BLOCKED if over limit.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_consume_send (SocketQUICFlow_T fc, size_t bytes);

/**
 * @brief Consume receive window (data received from peer).
 *
 * Updates bytes_received counter. Should trigger MAX_DATA update when
 * window is consumed significantly.
 *
 * @param fc    Flow control handle.
 * @param bytes Number of bytes consumed.
 *
 * @return QUIC_FLOW_OK on success, QUIC_FLOW_ERROR_BLOCKED if over limit.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_consume_recv (SocketQUICFlow_T fc, size_t bytes);

/**
 * @brief Update peer's MAX_DATA limit (from received MAX_DATA frame).
 *
 * Called when we receive a MAX_DATA frame from the peer, increasing
 * our send window.
 *
 * @param fc       Flow control handle.
 * @param max_data New maximum data value from peer.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_update_send_max (SocketQUICFlow_T fc, uint64_t max_data);

/**
 * @brief Update our MAX_DATA limit (to send in MAX_DATA frame).
 *
 * Called when we want to increase the window for the peer.
 *
 * @param fc       Flow control handle.
 * @param max_data New maximum data value to advertise.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_update_recv_max (SocketQUICFlow_T fc, uint64_t max_data);

/**
 * @brief Get available send window.
 *
 * @param fc Flow control handle.
 *
 * @return Number of bytes available to send, or 0 if blocked/NULL.
 */
extern uint64_t SocketQUICFlow_send_window (const SocketQUICFlow_T fc);

/**
 * @brief Get available receive window.
 *
 * @param fc Flow control handle.
 *
 * @return Number of bytes available to receive, or 0 if NULL.
 */
extern uint64_t SocketQUICFlow_recv_window (const SocketQUICFlow_T fc);

/**
 * @brief Create a new stream-level flow control state.
 *
 * @param arena      Memory arena for allocation.
 * @param stream_id  Stream ID this flow control applies to.
 *
 * @return New stream flow control handle, or NULL on allocation failure.
 */
extern SocketQUICFlowStream_T
SocketQUICFlowStream_new (Arena_T arena, uint64_t stream_id);

/**
 * @brief Initialize stream flow control with custom window sizes.
 *
 * @param fs             Stream flow control structure to initialize.
 * @param stream_id      Stream ID.
 * @param recv_max_data  Our initial MAX_STREAM_DATA limit.
 * @param send_max_data  Peer's initial MAX_STREAM_DATA limit.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result
SocketQUICFlowStream_init (SocketQUICFlowStream_T fs,
                           uint64_t stream_id,
                           uint64_t recv_max_data,
                           uint64_t send_max_data);

/**
 * @brief Check if we can send data on stream within flow control limits.
 *
 * @param fs    Stream flow control handle.
 * @param bytes Number of bytes to send.
 *
 * @return 1 if send is allowed, 0 if blocked by flow control.
 */
extern int
SocketQUICFlowStream_can_send (const SocketQUICFlowStream_T fs, size_t bytes);

/**
 * @brief Consume send window for stream (data sent to peer).
 *
 * @param fs    Stream flow control handle.
 * @param bytes Number of bytes consumed.
 *
 * @return QUIC_FLOW_OK on success, QUIC_FLOW_ERROR_BLOCKED if over limit.
 */
extern SocketQUICFlow_Result
SocketQUICFlowStream_consume_send (SocketQUICFlowStream_T fs, size_t bytes);

/**
 * @brief Consume receive window for stream (data received from peer).
 *
 * @param fs    Stream flow control handle.
 * @param bytes Number of bytes consumed.
 *
 * @return QUIC_FLOW_OK on success, QUIC_FLOW_ERROR_BLOCKED if over limit.
 */
extern SocketQUICFlow_Result
SocketQUICFlowStream_consume_recv (SocketQUICFlowStream_T fs, size_t bytes);

/**
 * @brief Update peer's MAX_STREAM_DATA (from received frame).
 *
 * @param fs       Stream flow control handle.
 * @param max_data New maximum stream data value from peer.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result
SocketQUICFlowStream_update_send_max (SocketQUICFlowStream_T fs,
                                      uint64_t max_data);

/**
 * @brief Update our MAX_STREAM_DATA (to send in frame).
 *
 * @param fs       Stream flow control handle.
 * @param max_data New maximum stream data value to advertise.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result
SocketQUICFlowStream_update_recv_max (SocketQUICFlowStream_T fs,
                                      uint64_t max_data);

/**
 * @brief Get available send window for stream.
 *
 * @param fs Stream flow control handle.
 *
 * @return Number of bytes available to send, or 0 if blocked/NULL.
 */
extern uint64_t
SocketQUICFlowStream_send_window (const SocketQUICFlowStream_T fs);

/**
 * @brief Get available receive window for stream.
 *
 * @param fs Stream flow control handle.
 *
 * @return Number of bytes available to receive, or 0 if NULL.
 */
extern uint64_t
SocketQUICFlowStream_recv_window (const SocketQUICFlowStream_T fs);

/**
 * @brief Update MAX_STREAMS limit for bidirectional streams.
 *
 * @param fc          Flow control handle.
 * @param max_streams New maximum bidirectional stream count.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_update_max_streams_bidi (SocketQUICFlow_T fc,
                                        uint64_t max_streams);

/**
 * @brief Update MAX_STREAMS limit for unidirectional streams.
 *
 * @param fc          Flow control handle.
 * @param max_streams New maximum unidirectional stream count.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_update_max_streams_uni (SocketQUICFlow_T fc,
                                       uint64_t max_streams);

/**
 * @brief Check if a new bidirectional stream can be created.
 *
 * @param fc Flow control handle.
 *
 * @return 1 if allowed, 0 if limit reached.
 */
extern int SocketQUICFlow_can_open_stream_bidi (const SocketQUICFlow_T fc);

/**
 * @brief Check if a new unidirectional stream can be created.
 *
 * @param fc Flow control handle.
 *
 * @return 1 if allowed, 0 if limit reached.
 */
extern int SocketQUICFlow_can_open_stream_uni (const SocketQUICFlow_T fc);

/**
 * @brief Increment bidirectional stream count.
 *
 * Call when a new bidirectional stream is opened.
 *
 * @param fc Flow control handle.
 *
 * @return QUIC_FLOW_OK on success, QUIC_FLOW_ERROR_BLOCKED if limit reached.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_open_stream_bidi (SocketQUICFlow_T fc);

/**
 * @brief Increment unidirectional stream count.
 *
 * Call when a new unidirectional stream is opened.
 *
 * @param fc Flow control handle.
 *
 * @return QUIC_FLOW_OK on success, QUIC_FLOW_ERROR_BLOCKED if limit reached.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_open_stream_uni (SocketQUICFlow_T fc);

/**
 * @brief Decrement bidirectional stream count.
 *
 * Call when a bidirectional stream is closed.
 *
 * @param fc Flow control handle.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_close_stream_bidi (SocketQUICFlow_T fc);

/**
 * @brief Decrement unidirectional stream count.
 *
 * Call when a unidirectional stream is closed.
 *
 * @param fc Flow control handle.
 *
 * @return QUIC_FLOW_OK on success, error code otherwise.
 */
extern SocketQUICFlow_Result
SocketQUICFlow_close_stream_uni (SocketQUICFlow_T fc);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code.
 *
 * @return Human-readable string.
 */
extern const char *SocketQUICFlow_result_string (SocketQUICFlow_Result result);

/** @} */

#endif /* SOCKETQUICFLOW_INCLUDED */

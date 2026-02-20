/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICCongestion.h
 * @brief QUIC NewReno Congestion Control (RFC 9002 Section 7).
 *
 * Implements NewReno congestion control for QUIC:
 *   - Slow start with exponential growth
 *   - Congestion avoidance with linear growth
 *   - Recovery phase with halved window
 *   - Persistent congestion detection (Section 7.6)
 *   - ECN-CE congestion signal handling
 *
 * The congestion controller is stateless with respect to bytes_in_flight;
 * the loss module (SocketQUICLoss) tracks bytes_in_flight. The transport
 * layer queries both to make send decisions.
 *
 * @defgroup quic_congestion QUIC Congestion Control
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9002#section-7
 */

#ifndef SOCKETQUICCONGESTION_INCLUDED
#define SOCKETQUICCONGESTION_INCLUDED

#include "core/Arena.h"
#include "quic/SocketQUICLoss.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Congestion control phase.
 */
typedef enum
{
  QUIC_CC_SLOW_START,      /**< Exponential window growth */
  QUIC_CC_RECOVERY,        /**< Window halved, waiting for recovery */
  QUIC_CC_CONGESTION_AVOID /**< Linear window growth */
} SocketQUICCongestion_Phase;

/**
 * @brief Opaque congestion controller handle.
 */
typedef struct SocketQUICCongestion *SocketQUICCongestion_T;

/**
 * @brief Create a new congestion controller.
 *
 * @param arena             Memory arena for allocations.
 * @param max_datagram_size Maximum datagram size (typically 1200).
 *
 * @return New controller, or NULL on failure.
 */
extern SocketQUICCongestion_T
SocketQUICCongestion_new (Arena_T arena, size_t max_datagram_size);

/**
 * @brief Reset congestion state to initial values.
 *
 * @param cc Controller to reset.
 */
extern void SocketQUICCongestion_reset (SocketQUICCongestion_T cc);

/**
 * @brief Check whether a packet can be sent under the congestion window.
 *
 * @param cc              Controller to query.
 * @param bytes_in_flight Current bytes in flight (from loss module).
 * @param packet_size     Size of packet to send.
 *
 * @return Non-zero if the packet can be sent, 0 if blocked.
 */
extern int SocketQUICCongestion_can_send (const SocketQUICCongestion_T cc,
                                          size_t bytes_in_flight,
                                          size_t packet_size);

/**
 * @brief Notify controller of acknowledged packets.
 *
 * @param cc                  Controller to update.
 * @param acked_bytes         Total in-flight bytes acknowledged.
 * @param latest_sent_time_us Sent time of the most recent acked packet.
 */
extern void
SocketQUICCongestion_on_packets_acked (SocketQUICCongestion_T cc,
                                       size_t acked_bytes,
                                       uint64_t latest_sent_time_us);

/**
 * @brief Notify controller of lost packets.
 *
 * @param cc                  Controller to update.
 * @param lost_bytes          Total in-flight bytes lost.
 * @param latest_sent_time_us Sent time of the most recent lost packet.
 */
extern void SocketQUICCongestion_on_packets_lost (SocketQUICCongestion_T cc,
                                                  size_t lost_bytes,
                                                  uint64_t latest_sent_time_us);

/**
 * @brief Notify controller of ECN Congestion Experienced signal.
 *
 * @param cc           Controller to update.
 * @param sent_time_us Sent time of the packet that triggered ECN-CE.
 */
extern void SocketQUICCongestion_on_ecn_ce (SocketQUICCongestion_T cc,
                                            uint64_t sent_time_us);

/**
 * @brief Notify controller of persistent congestion detection.
 *
 * Resets cwnd to minimum (RFC 9002 Section 7.6.2).
 *
 * @param cc Controller to update.
 */
extern void
SocketQUICCongestion_on_persistent_congestion (SocketQUICCongestion_T cc);

/**
 * @brief Get current congestion window.
 */
extern size_t SocketQUICCongestion_cwnd (const SocketQUICCongestion_T cc);

/**
 * @brief Get current slow start threshold.
 */
extern size_t SocketQUICCongestion_ssthresh (const SocketQUICCongestion_T cc);

/**
 * @brief Get current congestion control phase.
 */
extern SocketQUICCongestion_Phase
SocketQUICCongestion_phase (const SocketQUICCongestion_T cc);

/**
 * @brief Compute the persistent congestion duration (RFC 9002 Section 7.6.1).
 *
 * Duration = (smoothed_rtt + max(4*rttvar, granularity) + max_ack_delay)
 *            * QUIC_PERSISTENT_CONGESTION_THRESHOLD
 *
 * @param rtt              RTT estimation state.
 * @param max_ack_delay_us Peer's max_ack_delay in microseconds.
 *
 * @return Duration in microseconds.
 */
extern uint64_t
SocketQUICCongestion_persistent_duration (const SocketQUICLossRTT_T *rtt,
                                          uint64_t max_ack_delay_us);

/**
 * @brief Get human-readable name for a congestion control phase.
 */
extern const char *
SocketQUICCongestion_phase_name (SocketQUICCongestion_Phase phase);

/** @} */

#endif /* SOCKETQUICCONGESTION_INCLUDED */

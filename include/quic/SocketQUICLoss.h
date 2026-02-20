/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICLoss.h
 * @brief QUIC Loss Detection (RFC 9002).
 *
 * Implements:
 *   - RTT estimation (smoothed RTT, RTT variance)
 *   - Packet loss detection (time-based and packet threshold)
 *   - Probe Timeout (PTO) calculation
 *   - Sent packet tracking for acknowledgment processing
 *
 * RFC 9002 Section 6 - Loss Detection:
 *   - Packet threshold: 3 packets
 *   - Time threshold: max(kTimeThreshold * max_rtt, kGranularity)
 *   - PTO: smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
 *
 * Thread Safety: Loss detection operations are NOT thread-safe. Use external
 * synchronization when accessing from multiple threads.
 *
 * @defgroup quic_loss QUIC Loss Detection
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9002
 */

#ifndef SOCKETQUICLOSS_INCLUDED
#define SOCKETQUICLOSS_INCLUDED

#include "core/Arena.h"
#include "quic/SocketQUICFrame.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Initial RTT estimate in microseconds (333ms per RFC 9002).
 */
#define QUIC_LOSS_INITIAL_RTT_US 333000

/**
 * @brief Timer granularity in microseconds (1ms per RFC 9002).
 */
#define QUIC_LOSS_GRANULARITY_US 1000

/**
 * @brief Packet threshold for declaring loss (RFC 9002 Section 6.1.1).
 */
#define QUIC_LOSS_PACKET_THRESHOLD 3

/**
 * @brief Time threshold multiplier (RFC 9002 Section 6.1.2).
 *
 * Time threshold = kTimeThreshold * max(smoothed_rtt, latest_rtt).
 * Value is 9/8 = 1.125.
 */
#define QUIC_LOSS_TIME_THRESHOLD_NUM 9
#define QUIC_LOSS_TIME_THRESHOLD_DEN 8

/**
 * @brief Maximum number of sent packets to track per space.
 */
#define QUIC_LOSS_MAX_SENT_PACKETS 1024

/**
 * @brief Maximum number of ACK ranges to process per received ACK frame.
 *
 * QUIC peers can encode very large ACK ranges. We bound parsing (frame module)
 * and processing (loss module) to avoid CPU exhaustion when ranges include
 * packet numbers we never tracked.
 */
#define QUIC_LOSS_MAX_ACK_RANGES 256

/**
 * @brief Maximum PTO backoff exponent.
 */
#define QUIC_LOSS_MAX_PTO_COUNT 16

/**
 * @brief Information about a sent packet for loss detection.
 */
typedef struct SocketQUICLossSentPacket
{
  uint64_t packet_number; /**< Packet number */
  uint64_t sent_time_us;  /**< Time packet was sent (us) */
  size_t sent_bytes;      /**< Number of bytes in packet */
  int ack_eliciting;      /**< Non-zero if ack-eliciting */
  int in_flight;          /**< Non-zero if counts toward bytes_in_flight */
  int is_crypto;          /**< Non-zero if contains CRYPTO frames */

  struct SocketQUICLossSentPacket *next; /**< Free list pointer */

} SocketQUICLossSentPacket_T;

/**
 * @brief RTT estimation state.
 */
typedef struct SocketQUICLossRTT
{
  uint64_t smoothed_rtt; /**< Smoothed RTT in microseconds */
  uint64_t rtt_var;      /**< RTT variance in microseconds */
  uint64_t min_rtt;      /**< Minimum RTT observed */
  uint64_t latest_rtt;   /**< Most recent RTT sample */
  int has_sample;        /**< Non-zero if we have at least one sample */
  uint64_t first_rtt_sample_time; /**< Time of first RTT sample (0 = none) */

} SocketQUICLossRTT_T;

/**
 * @brief Loss detection state for a single packet number space.
 */
typedef struct SocketQUICLossState
{
  Arena_T arena; /**< Memory arena for allocations */

  /* Sent packet tracking */
  SocketQUICLossSentPacket_T **sent_packets; /**< Hash table of sent packets */
  size_t sent_packets_size;                  /**< Hash table size */
  size_t sent_count;                         /**< Number of tracked packets */
  SocketQUICLossSentPacket_T *free_list;     /**< Free list for reuse */

  /* Packet number tracking */
  uint64_t largest_acked; /**< Largest acknowledged packet number */
  uint64_t largest_sent;  /**< Largest sent packet number */
  uint64_t time_of_last_ack_eliciting; /**< Time of last ack-eliciting packet */

  /* Loss detection timers */
  uint64_t loss_time; /**< Time-based loss detection timer */

  /* Bytes in flight */
  size_t bytes_in_flight; /**< Bytes awaiting acknowledgment */

  /* Configuration */
  uint64_t
      max_ack_delay_us;   /**< Peer's max_ack_delay (from transport params) */
  int is_handshake_space; /**< Non-zero for Initial/Handshake */

} *SocketQUICLossState_T;

/**
 * @brief Callback for processing acknowledged packets.
 *
 * @param packet    Acknowledged packet information.
 * @param context   User-provided context.
 */
typedef void (*SocketQUICLoss_AckedCallback) (
    const SocketQUICLossSentPacket_T *packet, void *context);

/**
 * @brief Callback for processing lost packets.
 *
 * @param packet    Lost packet information.
 * @param context   User-provided context.
 */
typedef void (*SocketQUICLoss_LostCallback) (
    const SocketQUICLossSentPacket_T *packet, void *context);

/**
 * @brief Result codes for loss detection operations.
 */
typedef enum
{
  QUIC_LOSS_OK = 0,          /**< Operation succeeded */
  QUIC_LOSS_ERROR_NULL,      /**< NULL pointer argument */
  QUIC_LOSS_ERROR_DUPLICATE, /**< Packet number already tracked */
  QUIC_LOSS_ERROR_NOT_FOUND, /**< Packet number not found */
  QUIC_LOSS_ERROR_FULL,      /**< Too many sent packets tracked */
  QUIC_LOSS_ERROR_INVALID    /**< Invalid packet number or state */
} SocketQUICLoss_Result;

/**
 * @brief Create a new loss detection state for a packet number space.
 *
 * @param arena           Memory arena for allocations.
 * @param is_handshake    Non-zero for Initial/Handshake spaces.
 * @param max_ack_delay   Peer's max_ack_delay in microseconds.
 *
 * @return New loss state, or NULL on failure.
 */
extern SocketQUICLossState_T
SocketQUICLoss_new (Arena_T arena, int is_handshake, uint64_t max_ack_delay);

/**
 * @brief Reset loss detection state (e.g., for key update).
 *
 * @param state Loss state to reset.
 */
extern void SocketQUICLoss_reset (SocketQUICLossState_T state);

/**
 * @brief Record a sent packet for loss detection.
 *
 * @param state          Loss state to update.
 * @param packet_number  Packet number that was sent.
 * @param sent_time_us   Time packet was sent in microseconds.
 * @param sent_bytes     Number of bytes in packet.
 * @param ack_eliciting  Non-zero if packet is ack-eliciting.
 * @param in_flight      Non-zero if packet counts toward bytes_in_flight.
 * @param is_crypto      Non-zero if packet contains CRYPTO frames.
 *
 * @return QUIC_LOSS_OK on success, error code otherwise.
 */
extern SocketQUICLoss_Result
SocketQUICLoss_on_packet_sent (SocketQUICLossState_T state,
                               uint64_t packet_number,
                               uint64_t sent_time_us,
                               size_t sent_bytes,
                               int ack_eliciting,
                               int in_flight,
                               int is_crypto);

/**
 * @brief Process an ACK frame and detect lost packets.
 *
 * Processes all ACK ranges (not just largest_acked), updates RTT estimates,
 * detects lost packets based on packet and time thresholds, and invokes
 * callbacks for each acknowledged and lost packet.
 *
 * @param state          Loss state to update.
 * @param rtt            RTT estimation state (shared across spaces).
 * @param ack            Full ACK frame with ranges.
 * @param recv_time_us   Time ACK was received in microseconds.
 * @param acked_callback Callback for each acknowledged packet (optional).
 * @param lost_callback  Callback for each lost packet (optional).
 * @param context        User context for callbacks.
 * @param acked_count    Output: number of packets acknowledged (optional).
 * @param lost_count     Output: number of packets declared lost (optional).
 *
 * @return QUIC_LOSS_OK on success, error code otherwise.
 */
extern SocketQUICLoss_Result
SocketQUICLoss_on_ack_received (SocketQUICLossState_T state,
                                SocketQUICLossRTT_T *rtt,
                                const SocketQUICFrameAck_T *ack,
                                uint64_t recv_time_us,
                                SocketQUICLoss_AckedCallback acked_callback,
                                SocketQUICLoss_LostCallback lost_callback,
                                void *context,
                                size_t *acked_count,
                                size_t *lost_count);

/**
 * @brief Update RTT estimate with a new sample.
 *
 * @param rtt            RTT state to update.
 * @param latest_rtt_us  New RTT sample in microseconds.
 * @param ack_delay_us   ACK delay to subtract (for application data).
 * @param is_handshake   Non-zero if this is a handshake RTT sample.
 */
extern void SocketQUICLoss_update_rtt (SocketQUICLossRTT_T *rtt,
                                       uint64_t latest_rtt_us,
                                       uint64_t ack_delay_us,
                                       int is_handshake);

/**
 * @brief Calculate the Probe Timeout (PTO) interval.
 *
 * PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
 *
 * @param rtt             RTT estimation state.
 * @param max_ack_delay   Peer's max_ack_delay in microseconds.
 * @param pto_count       Current PTO count for backoff.
 *
 * @return PTO interval in microseconds.
 */
extern uint64_t SocketQUICLoss_get_pto (const SocketQUICLossRTT_T *rtt,
                                        uint64_t max_ack_delay,
                                        int pto_count);

/**
 * @brief Get the next loss detection timeout.
 *
 * Returns the earliest of: time-based loss timer or PTO timer.
 *
 * @param state        Loss state to check.
 * @param rtt          RTT estimation state.
 * @param pto_count    Current PTO count for backoff.
 * @param current_time Current time in microseconds.
 *
 * @return Timeout time in microseconds, or 0 if no timer set.
 */
extern uint64_t SocketQUICLoss_get_loss_time (const SocketQUICLossState_T state,
                                              const SocketQUICLossRTT_T *rtt,
                                              int pto_count,
                                              uint64_t current_time);

/**
 * @brief Handle loss detection timeout.
 *
 * Called when the loss detection timer fires.
 *
 * @param state         Loss state to update.
 * @param rtt           RTT estimation state.
 * @param current_time  Current time in microseconds.
 * @param lost_callback Callback for each lost packet.
 * @param context       User context for callback.
 * @param lost_count    Output: number of packets declared lost.
 *
 * @return QUIC_LOSS_OK on success, error code otherwise.
 */
extern SocketQUICLoss_Result
SocketQUICLoss_on_loss_timeout (SocketQUICLossState_T state,
                                SocketQUICLossRTT_T *rtt,
                                uint64_t current_time,
                                SocketQUICLoss_LostCallback lost_callback,
                                void *context,
                                size_t *lost_count);

/**
 * @brief Get the number of bytes currently in flight.
 *
 * @param state Loss state to query.
 *
 * @return Bytes in flight.
 */
extern size_t
SocketQUICLoss_bytes_in_flight (const SocketQUICLossState_T state);

/**
 * @brief Check if there are any packets awaiting acknowledgment.
 *
 * @param state Loss state to query.
 *
 * @return Non-zero if packets are in flight.
 */
extern int SocketQUICLoss_has_in_flight (const SocketQUICLossState_T state);

/**
 * @brief Initialize RTT state with default values.
 *
 * @param rtt RTT state to initialize.
 */
extern void SocketQUICLoss_init_rtt (SocketQUICLossRTT_T *rtt);

/**
 * @brief Get string representation of loss result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string.
 */
extern const char *SocketQUICLoss_result_string (SocketQUICLoss_Result result);

/** @} */

#endif /* SOCKETQUICLOSS_INCLUDED */

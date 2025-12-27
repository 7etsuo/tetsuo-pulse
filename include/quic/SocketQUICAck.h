/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICAck.h
 * @brief QUIC ACK generation and tracking (RFC 9000 Section 13.2).
 *
 * Implements:
 *   - Received packet number tracking with gap/range compression
 *   - ACK frame generation with delay calculation
 *   - ACK-eliciting packet counting for delayed ACK timer
 *   - ECN count tracking
 *
 * RFC 9000 Section 13.2 ACK Requirements:
 *   - Initial/Handshake packets: ACK immediately
 *   - Application Data: ACK within max_ack_delay or after 2 ack-eliciting
 *   - Always send ACK in response to ack-eliciting packet
 *
 * Thread Safety: ACK state operations are NOT thread-safe. Use external
 * synchronization when accessing from multiple threads.
 *
 * @defgroup quic_ack QUIC ACK Generation
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-13.2
 */

#ifndef SOCKETQUICACK_INCLUDED
#define SOCKETQUICACK_INCLUDED

#include "core/Arena.h"
#include "quic/SocketQUICFrame.h"

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Maximum number of ACK ranges to track.
 *
 * RFC 9000 doesn't specify a limit but practical implementations
 * typically limit to prevent memory exhaustion.
 */
#define QUIC_ACK_MAX_RANGES 256

/**
 * @brief Default max_ack_delay in microseconds (25ms per RFC 9000).
 */
#define QUIC_ACK_DEFAULT_MAX_DELAY_US 25000

/**
 * @brief Threshold of ack-eliciting packets before immediate ACK.
 *
 * RFC 9000 Section 13.2.1 recommends ACKing at least every 2 packets.
 */
#define QUIC_ACK_PACKET_THRESHOLD 2

/**
 * @brief Initial capacity for ACK range storage.
 *
 * Pre-allocated range capacity to avoid frequent reallocations.
 * The capacity will grow dynamically if more ranges are needed.
 */
#define QUIC_ACK_INITIAL_RANGE_CAPACITY 16

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * @brief A range of consecutively received packet numbers.
 *
 * Represents [start, end] inclusive.
 */
typedef struct SocketQUICAckRange
{
  uint64_t start; /**< First packet number in range */
  uint64_t end;   /**< Last packet number in range (inclusive) */

} SocketQUICAckRange_T;

/**
 * @brief ECN counts for a packet number space.
 */
typedef struct SocketQUICAckECN
{
  uint64_t ect0_count; /**< ECT(0) codepoint count */
  uint64_t ect1_count; /**< ECT(1) codepoint count */
  uint64_t ce_count;   /**< CE (Congestion Experienced) count */

} SocketQUICAckECN_T;

/**
 * @brief ACK state for a single packet number space.
 *
 * QUIC has three packet number spaces: Initial, Handshake, Application Data.
 * Each has independent ACK state.
 */
typedef struct SocketQUICAckState
{
  Arena_T arena; /**< Memory arena for allocations */

  /* Packet number tracking */
  SocketQUICAckRange_T *ranges; /**< Received packet ranges (sorted, descending) */
  size_t range_count;           /**< Number of active ranges */
  size_t range_capacity;        /**< Allocated range capacity */

  uint64_t largest_received;    /**< Largest packet number received */
  uint64_t largest_recv_time;   /**< Time when largest was received (us) */

  /* ACK generation state */
  int ack_pending;               /**< Non-zero if ACK should be sent */
  int ack_eliciting_count;       /**< Ack-eliciting packets since last ACK */
  uint64_t last_ack_sent_time;   /**< Time of last ACK sent (us) */

  /* Configuration */
  uint64_t max_ack_delay_us;     /**< Max delay before ACK (from transport params) */
  int is_handshake_space;        /**< Non-zero for Initial/Handshake (no delayed ACK) */

  /* ECN tracking */
  SocketQUICAckECN_T ecn_counts; /**< ECN codepoint counts */
  int ecn_validated;              /**< Non-zero if ECN is validated */

} *SocketQUICAckState_T;

/**
 * @brief Result codes for ACK operations.
 */
typedef enum
{
  QUIC_ACK_OK = 0,             /**< Operation succeeded */
  QUIC_ACK_ERROR_NULL,         /**< NULL pointer argument */
  QUIC_ACK_ERROR_DUPLICATE,    /**< Packet number already received */
  QUIC_ACK_ERROR_OLD,          /**< Packet number too old (pruned) */
  QUIC_ACK_ERROR_RANGE,        /**< Range limit exceeded */
  QUIC_ACK_ERROR_ENCODE,       /**< ACK frame encoding failed */
  QUIC_ACK_ERROR_BUFFER        /**< Output buffer too small */
} SocketQUICAck_Result;

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

/**
 * @brief Create a new ACK state for a packet number space.
 *
 * @param arena             Memory arena for allocations.
 * @param is_handshake      Non-zero for Initial/Handshake (no delayed ACK).
 * @param max_ack_delay_us  Max ACK delay in microseconds (0 for default).
 *
 * @return New ACK state, or NULL on failure.
 */
extern SocketQUICAckState_T
SocketQUICAck_new (Arena_T arena, int is_handshake, uint64_t max_ack_delay_us);

/**
 * @brief Reset ACK state (e.g., for key update).
 *
 * Clears all received packet ranges but preserves configuration.
 *
 * @param state ACK state to reset.
 */
extern void SocketQUICAck_reset (SocketQUICAckState_T state);

/* ============================================================================
 * Packet Recording
 * ============================================================================
 */

/**
 * @brief Record receipt of a packet.
 *
 * Updates the received packet ranges and ACK pending state.
 * For ack-eliciting packets, increments the counter.
 *
 * @param state           ACK state to update.
 * @param packet_number   Packet number that was received.
 * @param recv_time_us    Time of receipt in microseconds.
 * @param ack_eliciting   Non-zero if packet contained ack-eliciting frames.
 *
 * @return QUIC_ACK_OK on success, error code otherwise.
 */
extern SocketQUICAck_Result
SocketQUICAck_record_packet (SocketQUICAckState_T state, uint64_t packet_number,
                              uint64_t recv_time_us, int ack_eliciting);

/**
 * @brief Record ECN information from received packet.
 *
 * @param state    ACK state to update.
 * @param ecn_type ECN codepoint (0=not-ECT, 1=ECT0, 2=ECT1, 3=CE).
 */
extern void SocketQUICAck_record_ecn (SocketQUICAckState_T state, int ecn_type);

/* ============================================================================
 * ACK Generation
 * ============================================================================
 */

/**
 * @brief Check if an ACK should be sent now.
 *
 * Returns true if:
 *   - For handshake spaces: any ack-eliciting packet received
 *   - For application data: threshold packets received or delay expired
 *
 * @param state        ACK state to check.
 * @param current_time Current time in microseconds.
 *
 * @return Non-zero if ACK should be sent.
 */
extern int SocketQUICAck_should_send (const SocketQUICAckState_T state,
                                       uint64_t current_time);

/**
 * @brief Generate an ACK frame from current state.
 *
 * Encodes the ACK frame into the output buffer. Includes ECN if validated.
 *
 * @param state        ACK state with received packet info.
 * @param current_time Current time for ack_delay calculation.
 * @param out          Output buffer for encoded ACK frame.
 * @param out_size     Size of output buffer.
 * @param out_len      Output: actual bytes written.
 *
 * @return QUIC_ACK_OK on success, error code otherwise.
 */
extern SocketQUICAck_Result
SocketQUICAck_encode (SocketQUICAckState_T state, uint64_t current_time,
                       uint8_t *out, size_t out_size, size_t *out_len);

/**
 * @brief Mark ACK as sent, resetting pending state.
 *
 * Call after successfully sending an ACK frame.
 *
 * @param state        ACK state to update.
 * @param current_time Time when ACK was sent.
 */
extern void SocketQUICAck_mark_sent (SocketQUICAckState_T state, uint64_t current_time);

/* ============================================================================
 * Query Functions
 * ============================================================================
 */

/**
 * @brief Get the largest received packet number.
 *
 * @param state ACK state to query.
 *
 * @return Largest received packet number, or 0 if none received.
 */
extern uint64_t SocketQUICAck_get_largest (const SocketQUICAckState_T state);

/**
 * @brief Check if a packet number has been received.
 *
 * @param state         ACK state to query.
 * @param packet_number Packet number to check.
 *
 * @return Non-zero if packet was received.
 */
extern int SocketQUICAck_contains (const SocketQUICAckState_T state,
                                    uint64_t packet_number);

/**
 * @brief Get the number of tracked ACK ranges.
 *
 * @param state ACK state to query.
 *
 * @return Number of non-contiguous ranges.
 */
extern size_t SocketQUICAck_range_count (const SocketQUICAckState_T state);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of ACK result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string.
 */
extern const char *SocketQUICAck_result_string (SocketQUICAck_Result result);

/**
 * @brief Prune old packet numbers from tracking.
 *
 * Removes ranges older than the specified threshold to bound memory.
 *
 * @param state               ACK state to prune.
 * @param oldest_to_keep      Oldest packet number to retain.
 * @param removed_count       Output: number of ranges removed (optional).
 */
extern void SocketQUICAck_prune (SocketQUICAckState_T state,
                                  uint64_t oldest_to_keep,
                                  size_t *removed_count);

/** @} */

#endif /* SOCKETQUICACK_INCLUDED */

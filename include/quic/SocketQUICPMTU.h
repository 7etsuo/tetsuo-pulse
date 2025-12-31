/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICPMTU.h
 * @brief QUIC Path MTU Discovery (RFC 9000 Section 14).
 *
 * Implements Datagram Packetization Layer Path MTU Discovery (DPLPMTUD)
 * for QUIC connections:
 *
 * Initial Packet Padding (Section 14.1):
 *   - Client Initial packets MUST be >= 1200 bytes (padded if needed)
 *   - Server MUST discard Initial packets < 1200 bytes
 *   - Ensures path can deliver minimum QUIC packet size
 *
 * Path MTU Discovery (Section 14.3):
 *   - Uses DPLPMTUD (RFC 8899) for finding maximum datagram size
 *   - Sends PMTU probes with PING + PADDING frames
 *   - Probe loss does NOT trigger congestion response
 *   - Validates ICMP messages before using
 *   - Ignores ICMP claims < 1200 bytes
 *
 * Thread Safety: PMTU state should not be shared across threads.
 * Each connection maintains its own PMTU state.
 *
 * @defgroup quic_pmtu QUIC Path MTU Discovery Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-14
 * @see https://www.rfc-editor.org/rfc/rfc8899 (DPLPMTUD)
 */

#ifndef SOCKETQUICPMTU_INCLUDED
#define SOCKETQUICPMTU_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"

/* ============================================================================
 * Constants (RFC 9000 Section 14)
 * ============================================================================
 */

/**
 * @brief Minimum QUIC datagram size (RFC 9000 Section 14).
 *
 * All QUIC packets (except path validation) MUST be >= 1200 bytes.
 * Client Initial packets MUST be padded to this size.
 * Server MUST drop Initial packets smaller than this.
 */
#define QUIC_MIN_INITIAL_PACKET_SIZE 1200

/**
 * @brief Minimum PMTU accepted from ICMP messages.
 *
 * RFC 9000 Section 14.2: Endpoints MUST NOT reduce MTU below 1200 bytes.
 */
#define QUIC_MIN_PMTU 1200

/**
 * @brief Default initial PMTU (conservative IPv6 minimum).
 *
 * RFC 9000 Section 14: Start with 1200 bytes until path is validated.
 */
#define QUIC_DEFAULT_INITIAL_PMTU 1200

/**
 * @brief Maximum PMTU to probe (typical Ethernet MTU).
 *
 * RFC 8899: DPLPMTUD can probe up to interface MTU.
 * 1500 bytes is common Ethernet MTU.
 */
#define QUIC_MAX_PMTU 1500

/**
 * @brief PMTU probe timeout (milliseconds).
 *
 * RFC 8899 Section 5.1.2: Probes should timeout after PTO.
 * We use a conservative 3 seconds for PMTU probes.
 */
#define QUIC_PMTU_PROBE_TIMEOUT_MS 3000

/**
 * @brief Maximum number of PMTU probes in flight.
 *
 * Limit outstanding probes to avoid excessive loss detection.
 */
#define QUIC_MAX_PMTU_PROBES_IN_FLIGHT 3

/**
 * @brief PMTU probe increment in bytes.
 *
 * RFC 8899 Section 5.3: Probe size should increase incrementally.
 * 100 bytes provides reasonable granularity for path MTU discovery
 * between the minimum (1200) and typical maximum (1500) PMTU values.
 */
#define QUIC_PMTU_PROBE_INCREMENT 100

/* ============================================================================
 * DPLPMTUD States (RFC 8899 Section 5.2)
 * ============================================================================
 */

/**
 * @brief DPLPMTUD state machine states.
 */
typedef enum
{
  /**
   * Initial state - using base PMTU (1200 bytes).
   */
  QUIC_PMTU_STATE_INIT = 0,

  /**
   * Searching state - actively probing for larger PMTU.
   */
  QUIC_PMTU_STATE_SEARCHING = 1,

  /**
   * Search complete - found maximum PMTU.
   */
  QUIC_PMTU_STATE_COMPLETE = 2,

  /**
   * Error state - PMTU validation failed.
   */
  QUIC_PMTU_STATE_ERROR = 3
} SocketQUICPMTU_State;

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

/**
 * @brief Result codes for PMTU operations.
 */
typedef enum
{
  QUIC_PMTU_OK = 0,                /**< Success */
  QUIC_PMTU_ERROR_NULL = 1,        /**< NULL pointer argument */
  QUIC_PMTU_ERROR_SIZE = 2,        /**< Invalid size (< 1200 bytes) */
  QUIC_PMTU_ERROR_BUFFER = 3,      /**< Buffer too small for padding */
  QUIC_PMTU_ERROR_STATE = 4,       /**< Invalid state for operation */
  QUIC_PMTU_ERROR_PROBE_LIMIT = 5, /**< Too many probes in flight */
  QUIC_PMTU_ERROR_ARENA = 6        /**< Arena allocation failed */
} SocketQUICPMTU_Result;

/* ============================================================================
 * PMTU Probe Structure
 * ============================================================================
 */

/**
 * @brief PMTU probe tracking structure.
 *
 * Tracks a single PMTU probe packet to detect acknowledgment or loss.
 */
typedef struct SocketQUICPMTU_Probe
{
  /**
   * Packet number of the probe.
   */
  uint64_t packet_number;

  /**
   * Probe size in bytes.
   */
  size_t size;

  /**
   * Timestamp when probe was sent (milliseconds).
   */
  uint64_t sent_time_ms;

  /**
   * Next probe in linked list.
   */
  struct SocketQUICPMTU_Probe *next;
} SocketQUICPMTU_Probe_T;

/* ============================================================================
 * PMTU Discovery Context
 * ============================================================================
 */

/**
 * @brief PMTU discovery context (opaque handle).
 */
#define T SocketQUICPMTU_T
typedef struct T *T;

/**
 * @brief Internal PMTU discovery state.
 */
struct T
{
  /**
   * Arena for memory allocation.
   */
  Arena_T arena;

  /**
   * Current PMTU state.
   */
  SocketQUICPMTU_State state;

  /**
   * Current PMTU in bytes (validated path size).
   */
  size_t current_pmtu;

  /**
   * Target PMTU for next probe.
   */
  size_t target_pmtu;

  /**
   * Maximum PMTU to probe.
   */
  size_t max_pmtu;

  /**
   * Number of probes currently in flight.
   */
  int probes_in_flight;

  /**
   * Linked list of outstanding probes.
   */
  SocketQUICPMTU_Probe_T *probes;
};

/* ============================================================================
 * Public API
 * ============================================================================
 */

/**
 * @brief Create a new PMTU discovery context.
 *
 * @param arena Arena for memory allocation
 * @param initial_pmtu Initial PMTU value (default: 1200)
 * @param max_pmtu Maximum PMTU to probe (default: 1500)
 * @return New PMTU context, or NULL on allocation failure
 *
 * The PMTU context starts in INIT state with conservative MTU.
 * Call SocketQUICPMTU_start_discovery() to begin probing.
 */
extern T
SocketQUICPMTU_new (Arena_T arena, size_t initial_pmtu, size_t max_pmtu);

/**
 * @brief Free PMTU context resources.
 *
 * @param pmtu PMTU context to free
 *
 * Note: Memory is arena-allocated, so this just clears state.
 * Actual deallocation happens when arena is disposed.
 */
extern void SocketQUICPMTU_free (T *pmtu);

/**
 * @brief Pad Initial packet to minimum size (RFC 9000 Section 14.1).
 *
 * @param packet Packet buffer (will be modified in-place)
 * @param len Current packet length (will be updated)
 * @param max_len Maximum packet buffer size
 * @return QUIC_PMTU_OK on success, error code otherwise
 *
 * Pads packet with PADDING frames (0x00) to reach 1200 bytes.
 * Client MUST call this for Initial packets.
 * Server validates Initial packets with SocketQUICPMTU_validate_initial_size().
 *
 * Example:
 * @code
 *   uint8_t pkt[2048];
 *   size_t len = 950;
 *   SocketQUICPMTU_pad_initial(pkt, &len, sizeof(pkt));
 *   // len is now 1200, pkt[950..1199] filled with 0x00
 * @endcode
 */
extern SocketQUICPMTU_Result
SocketQUICPMTU_pad_initial (uint8_t *packet, size_t *len, size_t max_len);

/**
 * @brief Validate Initial packet size (RFC 9000 Section 14.1).
 *
 * @param packet_len Length of received Initial packet
 * @return QUIC_PMTU_OK if valid, QUIC_PMTU_ERROR_SIZE if too small
 *
 * Server MUST call this for received Initial packets.
 * Packets < 1200 bytes MUST be discarded.
 *
 * Example:
 * @code
 *   if (SocketQUICPMTU_validate_initial_size(packet_len) != QUIC_PMTU_OK) {
 *     // Discard packet - path cannot support QUIC
 *     return;
 *   }
 * @endcode
 */
extern SocketQUICPMTU_Result
SocketQUICPMTU_validate_initial_size (size_t packet_len);

/**
 * @brief Start PMTU discovery (enter SEARCHING state).
 *
 * @param pmtu PMTU context
 * @return QUIC_PMTU_OK on success, error code otherwise
 *
 * Transitions from INIT to SEARCHING state and prepares first probe.
 * Call SocketQUICPMTU_get_next_probe_size() to get probe size,
 * then SocketQUICPMTU_send_probe() after sending.
 */
extern SocketQUICPMTU_Result SocketQUICPMTU_start_discovery (T pmtu);

/**
 * @brief Get next PMTU probe size.
 *
 * @param pmtu PMTU context
 * @param size_out Output for probe size
 * @return QUIC_PMTU_OK on success, error code otherwise
 *
 * Returns the size for the next PMTU probe packet.
 * Application should send a packet of this size with PING + PADDING frames.
 */
extern SocketQUICPMTU_Result
SocketQUICPMTU_get_next_probe_size (T pmtu, size_t *size_out);

/**
 * @brief Record that a PMTU probe was sent.
 *
 * @param pmtu PMTU context
 * @param packet_number Packet number of the probe
 * @param size Probe size in bytes
 * @param sent_time_ms Timestamp when probe was sent
 * @return QUIC_PMTU_OK on success, error code otherwise
 *
 * Tracks the probe for acknowledgment or loss detection.
 * Call SocketQUICPMTU_probe_acked() when ACK received,
 * or SocketQUICPMTU_probe_lost() on timeout.
 */
extern SocketQUICPMTU_Result SocketQUICPMTU_send_probe (T pmtu,
                                                        uint64_t packet_number,
                                                        size_t size,
                                                        uint64_t sent_time_ms);

/**
 * @brief Mark probe as acknowledged (successful).
 *
 * @param pmtu PMTU context
 * @param packet_number Packet number that was acknowledged
 * @return QUIC_PMTU_OK on success, error code otherwise
 *
 * Updates current_pmtu if probe succeeded, transitions to COMPLETE if done.
 * Does NOT trigger congestion control response.
 */
extern SocketQUICPMTU_Result
SocketQUICPMTU_probe_acked (T pmtu, uint64_t packet_number);

/**
 * @brief Mark probe as lost (timeout or ICMP).
 *
 * @param pmtu PMTU context
 * @param packet_number Packet number that was lost
 * @return QUIC_PMTU_OK on success, error code otherwise
 *
 * Removes probe from tracking, does NOT update current_pmtu.
 * Does NOT trigger congestion control response (RFC 9000 Section 14.3).
 */
extern SocketQUICPMTU_Result
SocketQUICPMTU_probe_lost (T pmtu, uint64_t packet_number);

/**
 * @brief Process ICMP Packet Too Big message.
 *
 * @param pmtu PMTU context
 * @param icmp_mtu MTU value from ICMP message
 * @return QUIC_PMTU_OK on success, error code otherwise
 *
 * Validates ICMP message (RFC 9000 Section 14.2):
 * - MUST ignore claims < 1200 bytes
 * - SHOULD validate ICMP authenticity (source IP, original packet)
 * - Updates current_pmtu if valid and smaller than current
 */
extern SocketQUICPMTU_Result
SocketQUICPMTU_process_icmp (T pmtu, size_t icmp_mtu);

/**
 * @brief Get current PMTU value.
 *
 * @param pmtu PMTU context
 * @return Current PMTU in bytes (validated path MTU)
 *
 * Returns the maximum packet size that has been validated.
 * Application should not send packets larger than this value.
 */
extern size_t SocketQUICPMTU_get_current (T pmtu);

/**
 * @brief Get PMTU discovery state.
 *
 * @param pmtu PMTU context
 * @return Current DPLPMTUD state
 */
extern SocketQUICPMTU_State SocketQUICPMTU_get_state (T pmtu);

/**
 * @brief Check for timed-out probes.
 *
 * @param pmtu PMTU context
 * @param current_time_ms Current timestamp in milliseconds
 * @return QUIC_PMTU_OK on success, error code otherwise
 *
 * Marks probes as lost if they exceed QUIC_PMTU_PROBE_TIMEOUT_MS.
 * Call periodically (e.g., every 100ms) to clean up stale probes.
 */
extern SocketQUICPMTU_Result
SocketQUICPMTU_check_timeouts (T pmtu, uint64_t current_time_ms);

/**
 * @brief Get result code description string.
 *
 * @param result Result code
 * @return Human-readable description string
 */
extern const char *SocketQUICPMTU_result_string (SocketQUICPMTU_Result result);

#undef T

/** @} */

#endif /* SOCKETQUICPMTU_INCLUDED */

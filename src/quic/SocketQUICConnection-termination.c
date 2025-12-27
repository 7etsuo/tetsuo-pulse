/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICConnection-termination.c
 * @brief QUIC Connection Termination (RFC 9000 Section 10).
 *
 * Implements idle timeout, immediate close, and stateless reset mechanisms.
 *
 * State Machine:
 *   ACTIVE -> CLOSING (after sending CONNECTION_CLOSE)
 *   ACTIVE -> DRAINING (after receiving CONNECTION_CLOSE)
 *   CLOSING/DRAINING -> CLOSED (after 3*PTO timeout)
 *
 * Key Requirements:
 * - Idle timeout = min(local_max_idle_timeout, peer_max_idle_timeout)
 * - Reset timer on any packet sent/received
 * - PING frames keep connection alive
 * - CONNECTION_CLOSE triggers closing state
 * - Resend CONNECTION_CLOSE on any received packet while closing
 * - Enter draining state after 3*PTO in closing state
 * - Stateless reset: final 16 bytes = stateless reset token
 */

#include <string.h>
#include <stdint.h>
#include "quic/SocketQUICConnection.h"

/**
 * @brief Set idle timeout parameters for connection.
 * @param conn Connection instance.
 * @param local_timeout_ms Local max_idle_timeout in milliseconds.
 * @param peer_timeout_ms Peer's max_idle_timeout in milliseconds.
 *
 * Effective timeout is min(local, peer). If either is 0, idle timeout disabled.
 */
void
SocketQUICConnection_set_idle_timeout(SocketQUICConnection_T conn,
                                      uint64_t local_timeout_ms,
                                      uint64_t peer_timeout_ms)
{
  if (!conn)
    return;

  conn->local_max_idle_timeout_ms = local_timeout_ms;
  conn->peer_max_idle_timeout_ms = peer_timeout_ms;

  /* RFC 9000 Section 10.1: effective timeout is min of both values */
  /* If either is 0, idle timeout is disabled */
  if (local_timeout_ms == 0 || peer_timeout_ms == 0)
    {
      conn->idle_timeout_deadline_ms = 0;
      return;
    }

  uint64_t effective_timeout = local_timeout_ms < peer_timeout_ms
                                   ? local_timeout_ms
                                   : peer_timeout_ms;

  /* Set initial deadline (will be updated on packet activity) */
  conn->idle_timeout_deadline_ms = effective_timeout;
}

/**
 * @brief Reset idle timer based on packet activity.
 * @param conn Connection instance.
 * @param now_ms Current timestamp in milliseconds.
 *
 * Called when sending or receiving any packet.
 * Updates last activity timestamps and recalculates deadline.
 */
void
SocketQUICConnection_reset_idle_timer(SocketQUICConnection_T conn,
                                      uint64_t now_ms)
{
  if (!conn)
    return;

  /* Don't reset timer if idle timeout is disabled */
  if (conn->local_max_idle_timeout_ms == 0
      || conn->peer_max_idle_timeout_ms == 0)
    return;

  /* Update last activity timestamp */
  if (conn->last_packet_sent_ms == 0 || now_ms > conn->last_packet_sent_ms)
    conn->last_packet_sent_ms = now_ms;

  if (conn->last_packet_received_ms == 0
      || now_ms > conn->last_packet_received_ms)
    conn->last_packet_received_ms = now_ms;

  /* Recalculate deadline */
  uint64_t effective_timeout = conn->local_max_idle_timeout_ms
                                   < conn->peer_max_idle_timeout_ms
                                   ? conn->local_max_idle_timeout_ms
                                   : conn->peer_max_idle_timeout_ms;

  /* Prevent overflow */
  if (now_ms > UINT64_MAX - effective_timeout)
    conn->idle_timeout_deadline_ms = UINT64_MAX;
  else
    conn->idle_timeout_deadline_ms = now_ms + effective_timeout;
}

/**
 * @brief Check if connection has exceeded idle timeout.
 * @param conn Connection instance.
 * @param now_ms Current timestamp in milliseconds.
 * @return 1 if idle timeout exceeded, 0 otherwise.
 */
int
SocketQUICConnection_check_idle_timeout(SocketQUICConnection_T conn,
                                        uint64_t now_ms)
{
  if (!conn)
    return 0;

  /* Idle timeout disabled */
  if (conn->idle_timeout_deadline_ms == 0)
    return 0;

  /* Connection already closing or closed */
  if (conn->state >= QUIC_CONN_STATE_CLOSING)
    return 0;

  /* Check if deadline exceeded */
  return now_ms >= conn->idle_timeout_deadline_ms;
}

/**
 * @brief Initiate immediate connection close.
 * @param conn Connection instance.
 * @param error_code QUIC error code for CONNECTION_CLOSE frame.
 * @param now_ms Current timestamp in milliseconds.
 * @param pto_ms Probe Timeout (PTO) value in milliseconds.
 *
 * Transitions to CLOSING state. Caller must send CONNECTION_CLOSE frame.
 * Connection will transition to CLOSED after 3*PTO.
 */
void
SocketQUICConnection_initiate_close(SocketQUICConnection_T conn,
                                    uint64_t error_code,
                                    uint64_t now_ms,
                                    uint64_t pto_ms)
{
  if (!conn)
    return;

  /* Only transition from active states */
  if (conn->state >= QUIC_CONN_STATE_CLOSING)
    return;

  /* RFC 9000 Section 10.2: enter closing state */
  conn->state = QUIC_CONN_STATE_CLOSING;

  /* Calculate closing deadline: 3 * PTO */
  uint64_t timeout = pto_ms * QUIC_TERMINATION_PTO_MULTIPLIER;
  if (now_ms > UINT64_MAX - timeout)
    conn->closing_deadline_ms = UINT64_MAX;
  else
    conn->closing_deadline_ms = now_ms + timeout;

  /* Store error code in user_data for CONNECTION_CLOSE frame generation */
  /* Note: Actual frame sending is caller's responsibility */
  (void)error_code;
}

/**
 * @brief Enter draining state after receiving CONNECTION_CLOSE.
 * @param conn Connection instance.
 * @param now_ms Current timestamp in milliseconds.
 * @param pto_ms Probe Timeout (PTO) value in milliseconds.
 *
 * RFC 9000 Section 10.2.2: An endpoint that receives CONNECTION_CLOSE
 * enters the draining state. Must not send any packets (except stateless
 * reset). Connection will transition to CLOSED after 3*PTO.
 */
void
SocketQUICConnection_enter_draining(SocketQUICConnection_T conn,
                                    uint64_t now_ms,
                                    uint64_t pto_ms)
{
  if (!conn)
    return;

  /* Can enter draining from any state except already draining/closed */
  if (conn->state >= QUIC_CONN_STATE_DRAINING)
    return;

  /* RFC 9000 Section 10.2.2: enter draining state */
  conn->state = QUIC_CONN_STATE_DRAINING;

  /* Calculate draining deadline: 3 * PTO */
  uint64_t timeout = pto_ms * QUIC_TERMINATION_PTO_MULTIPLIER;
  if (now_ms > UINT64_MAX - timeout)
    conn->draining_deadline_ms = UINT64_MAX;
  else
    conn->draining_deadline_ms = now_ms + timeout;
}

/**
 * @brief Check if connection is in closing or draining state.
 * @param conn Connection instance.
 * @return 1 if closing or draining, 0 otherwise.
 *
 * Used to determine if new packets should be sent (forbidden in draining).
 */
int
SocketQUICConnection_is_closing_or_draining(SocketQUICConnection_T conn)
{
  if (!conn)
    return 0;

  return conn->state == QUIC_CONN_STATE_CLOSING
         || conn->state == QUIC_CONN_STATE_DRAINING;
}

/**
 * @brief Check if termination deadline has been reached.
 * @param conn Connection instance.
 * @param now_ms Current timestamp in milliseconds.
 * @return 1 if deadline reached and connection should close, 0 otherwise.
 *
 * Call periodically to detect when closing/draining timeout expires.
 * When returns 1, caller should transition to CLOSED state.
 */
int
SocketQUICConnection_check_termination_deadline(SocketQUICConnection_T conn,
                                                 uint64_t now_ms)
{
  if (!conn)
    return 0;

  if (conn->state == QUIC_CONN_STATE_CLOSING)
    {
      if (conn->closing_deadline_ms > 0 && now_ms >= conn->closing_deadline_ms)
        {
          conn->state = QUIC_CONN_STATE_CLOSED;
          return 1;
        }
    }
  else if (conn->state == QUIC_CONN_STATE_DRAINING)
    {
      if (conn->draining_deadline_ms > 0
          && now_ms >= conn->draining_deadline_ms)
        {
          conn->state = QUIC_CONN_STATE_CLOSED;
          return 1;
        }
    }

  return 0;
}

/**
 * @brief Set stateless reset token for this connection.
 * @param conn Connection instance.
 * @param token 16-byte stateless reset token.
 *
 * Server sets this token in transport parameters.
 * Used by peer to detect stateless resets.
 */
void
SocketQUICConnection_set_stateless_reset_token(SocketQUICConnection_T conn,
                                               const uint8_t *token)
{
  if (!conn || !token)
    return;

  memcpy(conn->stateless_reset_token, token, 16);
  conn->has_stateless_reset_token = 1;
}

/**
 * @brief Verify if packet is a stateless reset.
 * @param packet Packet data.
 * @param packet_len Packet length in bytes.
 * @param expected_token Expected 16-byte stateless reset token.
 * @return 1 if packet is a stateless reset with matching token, 0 otherwise.
 *
 * RFC 9000 Section 10.3: A stateless reset is a packet whose final 16 bytes
 * match the stateless reset token. Minimum packet size is 38 bytes to avoid
 * false positives with short packets.
 */
int
SocketQUICConnection_verify_stateless_reset(const uint8_t *packet,
                                            size_t packet_len,
                                            const uint8_t *expected_token)
{
  if (!packet || !expected_token)
    return 0;

  /* RFC 9000 Section 10.3.1: Minimum size to avoid collisions */
  if (packet_len < 38)
    return 0;

  /* Compare final 16 bytes with expected token */
  const uint8_t *actual_token = packet + packet_len - 16;
  return memcmp(actual_token, expected_token, 16) == 0;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICLoss.c
 * @brief QUIC Loss Detection (RFC 9002).
 */

#include "quic/SocketQUICLoss.h"
#include "quic/SocketQUICConstants.h"
#include "core/SocketUtil.h"

#include <inttypes.h>
#include <string.h>

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QUIC-LOSS"

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
    [QUIC_LOSS_OK] = "OK",
    [QUIC_LOSS_ERROR_NULL] = "NULL pointer argument",
    [QUIC_LOSS_ERROR_DUPLICATE] = "Duplicate packet number",
    [QUIC_LOSS_ERROR_NOT_FOUND] = "Packet number not found",
    [QUIC_LOSS_ERROR_FULL] = "Too many sent packets tracked",
    [QUIC_LOSS_ERROR_INVALID] = "Invalid packet number or state",
};

DEFINE_RESULT_STRING_FUNC (SocketQUICLoss, QUIC_LOSS_ERROR_INVALID)

/* ============================================================================
 * Internal Hash Functions
 * ============================================================================
 */

static unsigned
hash_pn (uint64_t pn)
{
  return (unsigned)(pn % QUIC_SENT_PACKET_HASH_SIZE);
}

static SocketQUICLossSentPacket_T *
find_sent_packet (SocketQUICLossState_T state, uint64_t pn)
{
  unsigned idx;
  SocketQUICLossSentPacket_T *p;

  if (state->sent_packets == NULL)
    return NULL;

  idx = hash_pn (pn);
  p = state->sent_packets[idx];

  while (p)
    {
      if (p->packet_number == pn)
        return p;
      p = p->next;
    }

  return NULL;
}

static void
insert_sent_packet (SocketQUICLossState_T state,
                    SocketQUICLossSentPacket_T *packet)
{
  unsigned idx = hash_pn (packet->packet_number);

  packet->next = state->sent_packets[idx];
  state->sent_packets[idx] = packet;
  state->sent_count++;
}

static void
remove_sent_packet (SocketQUICLossState_T state, uint64_t pn)
{
  unsigned idx;
  SocketQUICLossSentPacket_T **prev;
  SocketQUICLossSentPacket_T *p;

  if (state->sent_packets == NULL)
    return;

  idx = hash_pn (pn);
  prev = &state->sent_packets[idx];

  while (*prev)
    {
      p = *prev;
      if (p->packet_number == pn)
        {
          *prev = p->next;
          state->sent_count--;

          /* Return to free list */
          p->next = state->free_list;
          state->free_list = p;
          return;
        }
      prev = &p->next;
    }
}

static SocketQUICLossSentPacket_T *
alloc_sent_packet (SocketQUICLossState_T state)
{
  SocketQUICLossSentPacket_T *p;

  /* Try free list first */
  if (state->free_list)
    {
      p = state->free_list;
      state->free_list = p->next;
      memset (p, 0, sizeof (*p));
      return p;
    }

  /* Allocate new */
  p = CALLOC (state->arena, 1, sizeof (*p));
  return p;
}

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

SocketQUICLossState_T
SocketQUICLoss_new (Arena_T arena, int is_handshake, uint64_t max_ack_delay)
{
  SocketQUICLossState_T state;

  if (arena == NULL)
    return NULL;

  state = CALLOC (arena, 1, sizeof (*state));
  if (state == NULL)
    return NULL;

  state->arena = arena;
  state->is_handshake_space = is_handshake;
  state->max_ack_delay_us = max_ack_delay;

  /* Allocate hash table */
  state->sent_packets_size = QUIC_SENT_PACKET_HASH_SIZE;
  state->sent_packets
      = CALLOC (arena, state->sent_packets_size, sizeof (*state->sent_packets));
  if (state->sent_packets == NULL)
    return NULL;

  state->sent_count = 0;
  state->free_list = NULL;
  state->largest_acked = 0;
  state->largest_sent = 0;
  state->time_of_last_ack_eliciting = 0;
  state->loss_time = 0;
  state->bytes_in_flight = 0;

  return state;
}

void
SocketQUICLoss_reset (SocketQUICLossState_T state)
{
  if (state == NULL)
    return;

  /* Move all packets to free list */
  for (size_t i = 0; i < state->sent_packets_size; i++)
    {
      SocketQUICLossSentPacket_T *p = state->sent_packets[i];
      while (p)
        {
          SocketQUICLossSentPacket_T *next = p->next;
          p->next = state->free_list;
          state->free_list = p;
          p = next;
        }
      state->sent_packets[i] = NULL;
    }

  state->sent_count = 0;
  state->largest_acked = 0;
  state->largest_sent = 0;
  state->time_of_last_ack_eliciting = 0;
  state->loss_time = 0;
  state->bytes_in_flight = 0;
}

/* ============================================================================
 * RTT Functions
 * ============================================================================
 */

void
SocketQUICLoss_init_rtt (SocketQUICLossRTT_T *rtt)
{
  if (rtt == NULL)
    return;

  rtt->smoothed_rtt = QUIC_LOSS_INITIAL_RTT_US;
  rtt->rtt_var = QUIC_LOSS_INITIAL_RTT_US / 2;
  rtt->min_rtt = 0;
  rtt->latest_rtt = 0;
  rtt->has_sample = 0;
}

void
SocketQUICLoss_update_rtt (SocketQUICLossRTT_T *rtt, uint64_t latest_rtt_us,
                            uint64_t ack_delay_us, int is_handshake)
{
  uint64_t adjusted_rtt;
  uint64_t rtt_sample;
  int64_t diff;

  if (rtt == NULL)
    return;

  rtt->latest_rtt = latest_rtt_us;

  /* Update min_rtt (RFC 9002 Section 5.2) */
  if (rtt->min_rtt == 0 || latest_rtt_us < rtt->min_rtt)
    rtt->min_rtt = latest_rtt_us;

  /* First sample: initialize directly (RFC 9002 Section 5.3) */
  if (!rtt->has_sample)
    {
      rtt->smoothed_rtt = latest_rtt_us;
      rtt->rtt_var = latest_rtt_us / 2;
      rtt->has_sample = 1;
      return;
    }

  /* Adjust RTT for ack_delay (RFC 9002 Section 5.3)
   * Only subtract ack_delay for non-handshake packets
   * and only if it doesn't make RTT less than min_rtt
   */
  adjusted_rtt = latest_rtt_us;
  if (!is_handshake && ack_delay_us > 0)
    {
      if (adjusted_rtt > rtt->min_rtt + ack_delay_us)
        adjusted_rtt -= ack_delay_us;
      else if (adjusted_rtt > rtt->min_rtt)
        adjusted_rtt = rtt->min_rtt;
    }

  rtt_sample = adjusted_rtt;

  /* Update rtt_var and smoothed_rtt (RFC 9002 Section 5.3)
   * rttvar = (1 - 1/4) * rttvar + 1/4 * |smoothed_rtt - rtt_sample|
   * smoothed_rtt = (1 - 1/8) * smoothed_rtt + 1/8 * rtt_sample
   */
  diff = (int64_t)rtt->smoothed_rtt - (int64_t)rtt_sample;
  if (diff < 0)
    diff = -diff;

  rtt->rtt_var = (3 * rtt->rtt_var + (uint64_t)diff) / 4;
  rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + rtt_sample) / 8;
}

uint64_t
SocketQUICLoss_get_pto (const SocketQUICLossRTT_T *rtt, uint64_t max_ack_delay,
                         int pto_count)
{
  uint64_t pto;
  uint64_t timeout;

  if (rtt == NULL)
    return QUIC_LOSS_INITIAL_RTT_US * 3;

  /* PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay */
  timeout = rtt->rtt_var * 4;
  if (timeout < QUIC_LOSS_GRANULARITY_US)
    timeout = QUIC_LOSS_GRANULARITY_US;

  pto = rtt->smoothed_rtt + timeout + max_ack_delay;

  /* Apply backoff (2^pto_count) */
  if (pto_count > 0)
    {
      if (pto_count > QUIC_LOSS_MAX_PTO_COUNT)
        pto_count = QUIC_LOSS_MAX_PTO_COUNT;
      pto <<= pto_count;
    }

  return pto;
}

/* ============================================================================
 * Sent Packet Tracking
 * ============================================================================
 */

SocketQUICLoss_Result
SocketQUICLoss_on_packet_sent (SocketQUICLossState_T state,
                                uint64_t packet_number, uint64_t sent_time_us,
                                size_t sent_bytes, int ack_eliciting,
                                int in_flight, int is_crypto)
{
  SocketQUICLossSentPacket_T *packet;

  if (state == NULL)
    return QUIC_LOSS_ERROR_NULL;

  /* Check for duplicate */
  if (find_sent_packet (state, packet_number) != NULL)
    return QUIC_LOSS_ERROR_DUPLICATE;

  /* Check limit */
  if (state->sent_count >= QUIC_LOSS_MAX_SENT_PACKETS)
    {
      SOCKET_LOG_WARN_MSG ("Sent packet limit reached");
      return QUIC_LOSS_ERROR_FULL;
    }

  /* Allocate and populate */
  packet = alloc_sent_packet (state);
  if (packet == NULL)
    return QUIC_LOSS_ERROR_NULL;

  packet->packet_number = packet_number;
  packet->sent_time_us = sent_time_us;
  packet->sent_bytes = sent_bytes;
  packet->ack_eliciting = ack_eliciting;
  packet->in_flight = in_flight;
  packet->is_crypto = is_crypto;

  insert_sent_packet (state, packet);

  /* Update state */
  if (packet_number > state->largest_sent)
    state->largest_sent = packet_number;

  if (ack_eliciting)
    state->time_of_last_ack_eliciting = sent_time_us;

  if (in_flight)
    state->bytes_in_flight += sent_bytes;

  return QUIC_LOSS_OK;
}

/* ============================================================================
 * Internal Loss Detection
 * ============================================================================
 */

static uint64_t
get_loss_time_threshold (const SocketQUICLossRTT_T *rtt)
{
  uint64_t max_rtt;
  uint64_t threshold;

  if (rtt == NULL || !rtt->has_sample)
    return QUIC_LOSS_INITIAL_RTT_US;

  /* Use max of smoothed_rtt and latest_rtt */
  max_rtt = rtt->smoothed_rtt;
  if (rtt->latest_rtt > max_rtt)
    max_rtt = rtt->latest_rtt;

  /* threshold = kTimeThreshold * max_rtt = 9/8 * max_rtt */
  threshold = (max_rtt * QUIC_LOSS_TIME_THRESHOLD_NUM) / QUIC_LOSS_TIME_THRESHOLD_DEN;

  /* At least granularity */
  if (threshold < QUIC_LOSS_GRANULARITY_US)
    threshold = QUIC_LOSS_GRANULARITY_US;

  return threshold;
}

static void
mark_packet_lost (SocketQUICLossState_T state, SocketQUICLossSentPacket_T *p,
                  SocketQUICLoss_LostCallback lost_callback, void *context,
                  size_t *count)
{
  if (p->in_flight)
    state->bytes_in_flight -= p->sent_bytes;

  if (lost_callback)
    lost_callback (p, context);
  (*count)++;

  remove_sent_packet (state, p->packet_number);
}

static void
detect_lost_packets (SocketQUICLossState_T state, const SocketQUICLossRTT_T *rtt,
                     uint64_t current_time,
                     SocketQUICLoss_LostCallback lost_callback, void *context,
                     size_t *lost_count)
{
  uint64_t loss_delay;
  uint64_t pn_threshold;
  size_t count = 0;

  if (state->largest_acked == 0)
    {
      if (lost_count)
        *lost_count = 0;
      return;
    }

  loss_delay = get_loss_time_threshold (rtt);

  /* Packet threshold: packets more than 3 behind largest_acked */
  pn_threshold
      = state->largest_acked >= QUIC_LOSS_PACKET_THRESHOLD
            ? state->largest_acked - QUIC_LOSS_PACKET_THRESHOLD
            : 0;

  state->loss_time = 0;

  /* Check all sent packets */
  for (size_t i = 0; i < state->sent_packets_size; i++)
    {
      SocketQUICLossSentPacket_T *p = state->sent_packets[i];
      SocketQUICLossSentPacket_T *next;

      while (p)
        {
          next = p->next;

          /* Skip packets that haven't been acked yet or are >= largest_acked */
          if (p->packet_number >= state->largest_acked)
            {
              p = next;
              continue;
            }

          /* Check packet threshold */
          if (p->packet_number <= pn_threshold)
            {
              /* Lost by packet threshold */
              mark_packet_lost (state, p, lost_callback, context, &count);
              p = next;
              continue;
            }

          /* Check time threshold */
          if (current_time >= p->sent_time_us + loss_delay)
            {
              /* Lost by time threshold */
              mark_packet_lost (state, p, lost_callback, context, &count);
            }
          else
            {
              /* Not yet lost, but might be in the future.
               * Set loss_time to when it will be declared lost.
               */
              uint64_t packet_loss_time = p->sent_time_us + loss_delay;
              if (state->loss_time == 0 || packet_loss_time < state->loss_time)
                state->loss_time = packet_loss_time;
            }

          p = next;
        }
    }

  if (lost_count)
    *lost_count = count;
}

/* ============================================================================
 * ACK Processing
 * ============================================================================
 */

SocketQUICLoss_Result
SocketQUICLoss_on_ack_received (SocketQUICLossState_T state,
                                 SocketQUICLossRTT_T *rtt,
                                 uint64_t largest_acked, uint64_t ack_delay_us,
                                 uint64_t recv_time_us,
                                 SocketQUICLoss_LostCallback lost_callback,
                                 void *context, size_t *lost_count)
{
  SocketQUICLossSentPacket_T *largest_pkt;
  uint64_t latest_rtt;

  if (state == NULL || rtt == NULL)
    return QUIC_LOSS_ERROR_NULL;

  /* Find the largest acknowledged packet */
  largest_pkt = find_sent_packet (state, largest_acked);

  /* Update RTT if we have the packet */
  if (largest_pkt != NULL && recv_time_us >= largest_pkt->sent_time_us)
    {
      latest_rtt = recv_time_us - largest_pkt->sent_time_us;

      /* Only update RTT if this is a new largest_acked */
      if (largest_acked > state->largest_acked)
        {
          SocketQUICLoss_update_rtt (rtt, latest_rtt, ack_delay_us,
                                      state->is_handshake_space);
        }
    }

  /* Update largest_acked */
  if (largest_acked > state->largest_acked)
    state->largest_acked = largest_acked;

  /* Mark acknowledged packets */
  /* For simplicity, we just remove the largest_acked packet.
   * A full implementation would process ACK ranges.
   */
  if (largest_pkt != NULL)
    {
      if (largest_pkt->in_flight)
        state->bytes_in_flight -= largest_pkt->sent_bytes;
      remove_sent_packet (state, largest_acked);
    }

  /* Detect lost packets */
  detect_lost_packets (state, rtt, recv_time_us, lost_callback, context,
                       lost_count);

  return QUIC_LOSS_OK;
}

/* ============================================================================
 * Loss Detection Timers
 * ============================================================================
 */

uint64_t
SocketQUICLoss_get_loss_time (const SocketQUICLossState_T state,
                               const SocketQUICLossRTT_T *rtt, int pto_count,
                               uint64_t current_time)
{
  uint64_t pto_time;

  (void)current_time; /* May be used for relative timeout in future */

  if (state == NULL)
    return 0;

  /* If we have a time-based loss timer, use that */
  if (state->loss_time > 0)
    return state->loss_time;

  /* If no packets in flight, no timer needed */
  if (state->bytes_in_flight == 0)
    return 0;

  /* Calculate PTO timeout */
  if (state->time_of_last_ack_eliciting > 0)
    {
      pto_time = state->time_of_last_ack_eliciting
                 + SocketQUICLoss_get_pto (rtt, state->max_ack_delay_us,
                                            pto_count);
      return pto_time;
    }

  return 0;
}

SocketQUICLoss_Result
SocketQUICLoss_on_loss_timeout (SocketQUICLossState_T state,
                                 SocketQUICLossRTT_T *rtt, uint64_t current_time,
                                 SocketQUICLoss_LostCallback lost_callback,
                                 void *context, size_t *lost_count)
{
  if (state == NULL)
    return QUIC_LOSS_ERROR_NULL;

  /* Time-based loss detection */
  if (state->loss_time > 0 && current_time >= state->loss_time)
    {
      detect_lost_packets (state, rtt, current_time, lost_callback, context,
                           lost_count);
      return QUIC_LOSS_OK;
    }

  /* PTO timeout - caller should send probe */
  if (lost_count)
    *lost_count = 0;

  return QUIC_LOSS_OK;
}

/* ============================================================================
 * Query Functions
 * ============================================================================
 */

size_t
SocketQUICLoss_bytes_in_flight (const SocketQUICLossState_T state)
{
  if (state == NULL)
    return 0;
  return state->bytes_in_flight;
}

int
SocketQUICLoss_has_in_flight (const SocketQUICLossState_T state)
{
  if (state == NULL)
    return 0;
  return state->bytes_in_flight > 0 || state->sent_count > 0;
}

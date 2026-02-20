/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICCongestion.c
 * @brief QUIC NewReno Congestion Control (RFC 9002 Section 7).
 *
 * Appendix B of RFC 9002 provides the reference pseudocode.
 */

#ifdef SOCKET_HAS_TLS

#include "quic/SocketQUICCongestion.h"
#include "quic/SocketQUICConstants.h"
#include "core/SocketUtil.h"

#include <string.h>

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QUIC-CC"

struct SocketQUICCongestion
{
  Arena_T arena;
  size_t cwnd;
  size_t ssthresh;
  size_t max_datagram_size;
  SocketQUICCongestion_Phase phase;
  uint64_t recovery_start_time_us; /**< 0 when not in recovery */
};


/**
 * Check if sent_time falls within the current recovery period.
 */
static int
in_congestion_recovery (const SocketQUICCongestion_T cc, uint64_t sent_time_us)
{
  return cc->recovery_start_time_us > 0
         && sent_time_us <= cc->recovery_start_time_us;
}

/**
 * Enter recovery: halve cwnd, set ssthresh, record recovery start.
 * RFC 9002 Appendix B.6 (OnCongestionEvent).
 */
static void
enter_recovery (SocketQUICCongestion_T cc)
{
  size_t new_ssthresh = cc->cwnd * QUIC_LOSS_REDUCTION_FACTOR_NUM
                        / QUIC_LOSS_REDUCTION_FACTOR_DEN;

  if (new_ssthresh < QUIC_MIN_CWND)
    new_ssthresh = QUIC_MIN_CWND;

  cc->ssthresh = new_ssthresh;
  cc->cwnd = new_ssthresh;
  cc->recovery_start_time_us = Socket_get_monotonic_us ();
  cc->phase = QUIC_CC_RECOVERY;
}

SocketQUICCongestion_T
SocketQUICCongestion_new (Arena_T arena, size_t max_datagram_size)
{
  SocketQUICCongestion_T cc;

  if (arena == NULL)
    return NULL;

  cc = CALLOC (arena, 1, sizeof (*cc));
  if (cc == NULL)
    return NULL;

  cc->arena = arena;
  cc->max_datagram_size
      = max_datagram_size > 0 ? max_datagram_size : QUIC_MAX_DATAGRAM_SIZE;
  cc->cwnd = QUIC_INITIAL_CWND;
  cc->ssthresh = QUIC_MAX_CWND;
  cc->phase = QUIC_CC_SLOW_START;
  cc->recovery_start_time_us = 0;

  return cc;
}

void
SocketQUICCongestion_reset (SocketQUICCongestion_T cc)
{
  if (cc == NULL)
    return;

  cc->cwnd = QUIC_INITIAL_CWND;
  cc->ssthresh = QUIC_MAX_CWND;
  cc->phase = QUIC_CC_SLOW_START;
  cc->recovery_start_time_us = 0;
}

int
SocketQUICCongestion_can_send (const SocketQUICCongestion_T cc,
                               size_t bytes_in_flight,
                               size_t packet_size)
{
  if (cc == NULL)
    return 1; /* No CC = allow send */

  return bytes_in_flight + packet_size <= cc->cwnd;
}

void
SocketQUICCongestion_on_packets_acked (SocketQUICCongestion_T cc,
                                       size_t acked_bytes,
                                       uint64_t latest_sent_time_us)
{
  if (cc == NULL || acked_bytes == 0)
    return;

  /* If in recovery, check if we can exit */
  if (cc->phase == QUIC_CC_RECOVERY)
    {
      if (latest_sent_time_us > cc->recovery_start_time_us)
        {
          /* ACK of packet sent after recovery started → exit recovery */
          cc->recovery_start_time_us = 0;
          cc->phase = QUIC_CC_CONGESTION_AVOID;
        }
      else
        {
          /* Still in recovery — no cwnd growth */
          return;
        }
    }

  /* Grow cwnd based on phase */
  if (cc->phase == QUIC_CC_SLOW_START)
    {
      /* Exponential growth: cwnd += acked_bytes */
      cc->cwnd += acked_bytes;

      /* Cap at ssthresh to transition to congestion avoidance */
      if (cc->cwnd >= cc->ssthresh)
        {
          cc->cwnd = cc->ssthresh;
          cc->phase = QUIC_CC_CONGESTION_AVOID;
        }
    }
  else
    {
      /* Congestion avoidance: linear growth
       * cwnd += max_datagram_size * acked_bytes / cwnd
       * (RFC 9002 Appendix B.5)
       */
      size_t increment = cc->max_datagram_size * acked_bytes / cc->cwnd;
      if (increment == 0)
        increment = 1; /* Ensure at least 1 byte growth */
      cc->cwnd += increment;
    }

  /* Cap at maximum */
  if (cc->cwnd > QUIC_MAX_CWND)
    cc->cwnd = QUIC_MAX_CWND;
}

void
SocketQUICCongestion_on_packets_lost (SocketQUICCongestion_T cc,
                                      size_t lost_bytes,
                                      uint64_t latest_sent_time_us)
{
  if (cc == NULL || lost_bytes == 0)
    return;

  /* If the lost packet was sent during recovery, don't re-enter */
  if (in_congestion_recovery (cc, latest_sent_time_us))
    return;

  enter_recovery (cc);
}

void
SocketQUICCongestion_on_ecn_ce (SocketQUICCongestion_T cc,
                                uint64_t sent_time_us)
{
  if (cc == NULL)
    return;

  /* ECN-CE treated same as loss for congestion signal */
  if (in_congestion_recovery (cc, sent_time_us))
    return;

  enter_recovery (cc);
}

void
SocketQUICCongestion_on_persistent_congestion (SocketQUICCongestion_T cc)
{
  if (cc == NULL)
    return;

  /* RFC 9002 Section 7.6.2: reset to minimum window */
  cc->cwnd = QUIC_MIN_CWND;
  cc->ssthresh = QUIC_MAX_CWND;
  cc->recovery_start_time_us = 0;
  cc->phase = QUIC_CC_SLOW_START;
}

size_t
SocketQUICCongestion_cwnd (const SocketQUICCongestion_T cc)
{
  if (cc == NULL)
    return 0;
  return cc->cwnd;
}

size_t
SocketQUICCongestion_ssthresh (const SocketQUICCongestion_T cc)
{
  if (cc == NULL)
    return 0;
  return cc->ssthresh;
}

SocketQUICCongestion_Phase
SocketQUICCongestion_phase (const SocketQUICCongestion_T cc)
{
  if (cc == NULL)
    return QUIC_CC_SLOW_START;
  return cc->phase;
}

uint64_t
SocketQUICCongestion_persistent_duration (const SocketQUICLossRTT_T *rtt,
                                          uint64_t max_ack_delay_us)
{
  uint64_t pto;
  uint64_t rttvar_term;

  if (rtt == NULL || !rtt->has_sample)
    return 0;

  /* PTO base = smoothed_rtt + max(4 * rttvar, granularity) + max_ack_delay */
  rttvar_term = rtt->rtt_var * 4;
  if (rttvar_term < QUIC_LOSS_GRANULARITY_US)
    rttvar_term = QUIC_LOSS_GRANULARITY_US;

  pto = rtt->smoothed_rtt + rttvar_term + max_ack_delay_us;

  return pto * QUIC_PERSISTENT_CONGESTION_THRESHOLD;
}

static const char *phase_names[] = {
  [QUIC_CC_SLOW_START] = "SLOW_START",
  [QUIC_CC_RECOVERY] = "RECOVERY",
  [QUIC_CC_CONGESTION_AVOID] = "CONGESTION_AVOIDANCE",
};

const char *
SocketQUICCongestion_phase_name (SocketQUICCongestion_Phase phase)
{
  if (phase > QUIC_CC_CONGESTION_AVOID)
    return "UNKNOWN";
  return phase_names[phase];
}

void
SocketQUICCongestion_process_ack (SocketQUICCongestion_T cc,
                                  const SocketQUICCongestion_AckCtx *actx,
                                  const SocketQUICLossRTT_T *rtt,
                                  SocketQUICLossState_T loss,
                                  uint64_t ecn_ce_count,
                                  int is_ecn,
                                  size_t lost_count,
                                  uint64_t *prev_ecn_ce_count)
{
  if (!cc || !actx)
    return;

  if (actx->acked_bytes > 0)
    SocketQUICCongestion_on_packets_acked (
        cc, actx->acked_bytes, actx->latest_acked_sent_time);

  if (actx->lost_bytes > 0)
    SocketQUICCongestion_on_packets_lost (
        cc, actx->lost_bytes, actx->latest_lost_sent_time);

  if (is_ecn && prev_ecn_ce_count && ecn_ce_count > *prev_ecn_ce_count)
    {
      SocketQUICCongestion_on_ecn_ce (cc, actx->latest_acked_sent_time);
      *prev_ecn_ce_count = ecn_ce_count;
    }

  if (lost_count > 0 && rtt && rtt->first_rtt_sample_time > 0 && loss)
    {
      uint64_t pc_dur = SocketQUICCongestion_persistent_duration (
          rtt, loss->max_ack_delay_us);
      if (pc_dur > 0
          && actx->latest_lost_sent_time - rtt->first_rtt_sample_time > pc_dur)
        SocketQUICCongestion_on_persistent_congestion (cc);
    }
}

#endif /* SOCKET_HAS_TLS */

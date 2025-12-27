/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICAck.c
 * @brief QUIC ACK generation and tracking (RFC 9000 Section 13.2).
 */

#include "quic/SocketQUICAck.h"
#include "quic/SocketQUICVarInt.h"
#include "core/SocketUtil.h"

#include <inttypes.h>
#include <string.h>

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QUIC-ACK"

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
    [QUIC_ACK_OK] = "OK",
    [QUIC_ACK_ERROR_NULL] = "NULL pointer argument",
    [QUIC_ACK_ERROR_DUPLICATE] = "Duplicate packet number",
    [QUIC_ACK_ERROR_OLD] = "Packet number too old",
    [QUIC_ACK_ERROR_RANGE] = "Range limit exceeded",
    [QUIC_ACK_ERROR_ENCODE] = "ACK frame encoding failed",
    [QUIC_ACK_ERROR_BUFFER] = "Output buffer too small",
};

const char *
SocketQUICAck_result_string (SocketQUICAck_Result result)
{
  if (result < 0 || result > QUIC_ACK_ERROR_BUFFER)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

SocketQUICAckState_T
SocketQUICAck_new (Arena_T arena, int is_handshake, uint64_t max_ack_delay_us)
{
  SocketQUICAckState_T state;

  if (arena == NULL)
    return NULL;

  state = CALLOC (arena, 1, sizeof (*state));
  if (state == NULL)
    return NULL;

  state->arena = arena;
  state->is_handshake_space = is_handshake;
  state->max_ack_delay_us
      = (max_ack_delay_us > 0) ? max_ack_delay_us : QUIC_ACK_DEFAULT_MAX_DELAY_US;

  /* Pre-allocate some range capacity */
  state->range_capacity = 16;
  state->ranges = CALLOC (arena, state->range_capacity, sizeof (*state->ranges));
  if (state->ranges == NULL)
    return NULL;

  state->range_count = 0;
  state->largest_received = 0;
  state->largest_recv_time = 0;
  state->ack_pending = 0;
  state->ack_eliciting_count = 0;
  state->last_ack_sent_time = 0;
  state->ecn_validated = 0;

  return state;
}

void
SocketQUICAck_reset (SocketQUICAckState_T state)
{
  if (state == NULL)
    return;

  state->range_count = 0;
  state->largest_received = 0;
  state->largest_recv_time = 0;
  state->ack_pending = 0;
  state->ack_eliciting_count = 0;
  memset (&state->ecn_counts, 0, sizeof (state->ecn_counts));
  state->ecn_validated = 0;
}

/* ============================================================================
 * Internal Range Functions
 * ============================================================================
 */

static int
grow_ranges (SocketQUICAckState_T state)
{
  size_t new_capacity;
  SocketQUICAckRange_T *new_ranges;

  if (state->range_capacity >= QUIC_ACK_MAX_RANGES)
    return 0;

  new_capacity = state->range_capacity * 2;
  if (new_capacity > QUIC_ACK_MAX_RANGES)
    new_capacity = QUIC_ACK_MAX_RANGES;

  new_ranges = CALLOC (state->arena, new_capacity, sizeof (*new_ranges));
  if (new_ranges == NULL)
    return 0;

  memcpy (new_ranges, state->ranges,
          state->range_count * sizeof (*state->ranges));
  state->ranges = new_ranges;
  state->range_capacity = new_capacity;

  return 1;
}

static int
find_range_index (const SocketQUICAckState_T state, uint64_t pn, size_t *idx)
{
  /* Ranges are sorted in descending order by start */
  for (size_t i = 0; i < state->range_count; i++)
    {
      if (pn >= state->ranges[i].start && pn <= state->ranges[i].end)
        {
          *idx = i;
          return 1; /* Found containing range */
        }
      if (pn > state->ranges[i].end)
        {
          *idx = i;
          return 0; /* Insert before this range */
        }
    }
  *idx = state->range_count;
  return 0; /* Insert at end */
}

static void
merge_ranges (SocketQUICAckState_T state, size_t idx)
{
  /* Merge with previous range if adjacent */
  while (idx > 0
         && state->ranges[idx - 1].start == state->ranges[idx].end + 1)
    {
      state->ranges[idx].end = state->ranges[idx - 1].end;
      memmove (&state->ranges[idx - 1], &state->ranges[idx],
               (state->range_count - idx) * sizeof (*state->ranges));
      state->range_count--;
      idx--;
    }

  /* Merge with next range if adjacent */
  while (idx < state->range_count - 1
         && state->ranges[idx + 1].end + 1 == state->ranges[idx].start)
    {
      state->ranges[idx].start = state->ranges[idx + 1].start;
      memmove (&state->ranges[idx + 1], &state->ranges[idx + 2],
               (state->range_count - idx - 2) * sizeof (*state->ranges));
      state->range_count--;
    }
}

/* ============================================================================
 * Packet Recording
 * ============================================================================
 */

SocketQUICAck_Result
SocketQUICAck_record_packet (SocketQUICAckState_T state, uint64_t packet_number,
                              uint64_t recv_time_us, int ack_eliciting)
{
  size_t idx;
  int found;

  if (state == NULL)
    return QUIC_ACK_ERROR_NULL;

  /* Check for duplicate */
  found = find_range_index (state, packet_number, &idx);
  if (found)
    {
      SOCKET_LOG_DEBUG_MSG ("Duplicate packet %" PRIu64, packet_number);
      return QUIC_ACK_ERROR_DUPLICATE;
    }

  /* Update largest received */
  if (state->range_count == 0 || packet_number > state->largest_received)
    {
      state->largest_received = packet_number;
      state->largest_recv_time = recv_time_us;
    }

  /* Check if we can extend an existing range */
  if (idx > 0 && state->ranges[idx - 1].start == packet_number + 1)
    {
      /* Extend previous range down */
      state->ranges[idx - 1].start = packet_number;
      merge_ranges (state, idx - 1);
    }
  else if (idx < state->range_count
           && state->ranges[idx].end + 1 == packet_number)
    {
      /* Extend current range up */
      state->ranges[idx].end = packet_number;
      merge_ranges (state, idx);
    }
  else
    {
      /* Need to insert a new range */
      if (state->range_count >= state->range_capacity)
        {
          if (!grow_ranges (state))
            {
              SOCKET_LOG_WARN_MSG ("ACK range limit reached");
              return QUIC_ACK_ERROR_RANGE;
            }
        }

      /* Insert at idx */
      memmove (&state->ranges[idx + 1], &state->ranges[idx],
               (state->range_count - idx) * sizeof (*state->ranges));
      state->ranges[idx].start = packet_number;
      state->ranges[idx].end = packet_number;
      state->range_count++;
    }

  /* Update ACK pending state */
  if (ack_eliciting)
    {
      state->ack_eliciting_count++;
      state->ack_pending = 1;
    }

  return QUIC_ACK_OK;
}

void
SocketQUICAck_record_ecn (SocketQUICAckState_T state, int ecn_type)
{
  if (state == NULL)
    return;

  switch (ecn_type)
    {
    case 1: /* ECT(0) */
      state->ecn_counts.ect0_count++;
      break;
    case 2: /* ECT(1) */
      state->ecn_counts.ect1_count++;
      break;
    case 3: /* CE */
      state->ecn_counts.ce_count++;
      break;
    default:
      /* Not-ECT, don't count */
      break;
    }
}

/* ============================================================================
 * ACK Generation
 * ============================================================================
 */

int
SocketQUICAck_should_send (const SocketQUICAckState_T state,
                            uint64_t current_time)
{
  uint64_t elapsed;

  if (state == NULL || !state->ack_pending)
    return 0;

  if (state->range_count == 0)
    return 0;

  /* Initial/Handshake: always ACK immediately */
  if (state->is_handshake_space)
    return 1;

  /* Application Data: ACK after threshold packets */
  if (state->ack_eliciting_count >= QUIC_ACK_PACKET_THRESHOLD)
    return 1;

  /* Application Data: ACK after max_ack_delay */
  if (state->largest_recv_time > 0)
    {
      elapsed = current_time - state->largest_recv_time;
      if (elapsed >= state->max_ack_delay_us)
        return 1;
    }

  return 0;
}

SocketQUICAck_Result
SocketQUICAck_encode (SocketQUICAckState_T state, uint64_t current_time,
                       uint8_t *out, size_t out_size, size_t *out_len)
{
  uint8_t *p;
  size_t remaining;
  size_t n;
  uint64_t ack_delay;
  uint64_t first_ack_range;
  int has_ecn;

  if (state == NULL || out == NULL || out_len == NULL)
    return QUIC_ACK_ERROR_NULL;

  if (state->range_count == 0)
    {
      *out_len = 0;
      return QUIC_ACK_OK;
    }

  p = out;
  remaining = out_size;

  /* Calculate ack_delay in microseconds, then convert to frame format.
   * Per RFC 9000, ack_delay is in units of ack_delay_exponent microseconds.
   * Default exponent is 3, so divide by 8 (2^3).
   */
  if (current_time > state->largest_recv_time)
    ack_delay = (current_time - state->largest_recv_time) >> 3;
  else
    ack_delay = 0;

  /* Determine if we should include ECN */
  has_ecn = state->ecn_validated
            && (state->ecn_counts.ect0_count > 0
                || state->ecn_counts.ect1_count > 0
                || state->ecn_counts.ce_count > 0);

  /* Frame type: 0x02 for ACK, 0x03 for ACK_ECN */
  if (remaining < 1)
    return QUIC_ACK_ERROR_BUFFER;
  *p++ = has_ecn ? 0x03 : 0x02;
  remaining--;

  /* Largest Acknowledged */
  n = SocketQUICVarInt_encode (state->largest_received, p, remaining);
  if (n == 0)
    return QUIC_ACK_ERROR_BUFFER;
  p += n;
  remaining -= n;

  /* ACK Delay */
  n = SocketQUICVarInt_encode (ack_delay, p, remaining);
  if (n == 0)
    return QUIC_ACK_ERROR_BUFFER;
  p += n;
  remaining -= n;

  /* ACK Range Count (number of gap+range pairs after first range) */
  n = SocketQUICVarInt_encode (
      state->range_count > 0 ? state->range_count - 1 : 0, p, remaining);
  if (n == 0)
    return QUIC_ACK_ERROR_BUFFER;
  p += n;
  remaining -= n;

  /* First ACK Range (largest - first range start) */
  first_ack_range = state->ranges[0].end - state->ranges[0].start;
  n = SocketQUICVarInt_encode (first_ack_range, p, remaining);
  if (n == 0)
    return QUIC_ACK_ERROR_BUFFER;
  p += n;
  remaining -= n;

  /* Additional ranges (Gap, ACK Range pairs) */
  for (size_t i = 1; i < state->range_count; i++)
    {
      uint64_t gap;
      uint64_t ack_range_len;

      /* Gap = prev_start - current_end - 2
       * (since prev_start is exclusive and we subtract one for each endpoint)
       */
      gap = state->ranges[i - 1].start - state->ranges[i].end - 2;

      n = SocketQUICVarInt_encode (gap, p, remaining);
      if (n == 0)
        return QUIC_ACK_ERROR_BUFFER;
      p += n;
      remaining -= n;

      /* ACK Range length */
      ack_range_len = state->ranges[i].end - state->ranges[i].start;
      n = SocketQUICVarInt_encode (ack_range_len, p, remaining);
      if (n == 0)
        return QUIC_ACK_ERROR_BUFFER;
      p += n;
      remaining -= n;
    }

  /* ECN counts (if ECN frame type) */
  if (has_ecn)
    {
      n = SocketQUICVarInt_encode (state->ecn_counts.ect0_count, p, remaining);
      if (n == 0)
        return QUIC_ACK_ERROR_BUFFER;
      p += n;
      remaining -= n;

      n = SocketQUICVarInt_encode (state->ecn_counts.ect1_count, p, remaining);
      if (n == 0)
        return QUIC_ACK_ERROR_BUFFER;
      p += n;
      remaining -= n;

      n = SocketQUICVarInt_encode (state->ecn_counts.ce_count, p, remaining);
      if (n == 0)
        return QUIC_ACK_ERROR_BUFFER;
      p += n;
      remaining -= n;
    }

  *out_len = (size_t)(p - out);
  return QUIC_ACK_OK;
}

void
SocketQUICAck_mark_sent (SocketQUICAckState_T state, uint64_t current_time)
{
  if (state == NULL)
    return;

  state->ack_pending = 0;
  state->ack_eliciting_count = 0;
  state->last_ack_sent_time = current_time;
}

/* ============================================================================
 * Query Functions
 * ============================================================================
 */

uint64_t
SocketQUICAck_get_largest (const SocketQUICAckState_T state)
{
  if (state == NULL || state->range_count == 0)
    return 0;
  return state->largest_received;
}

int
SocketQUICAck_contains (const SocketQUICAckState_T state, uint64_t packet_number)
{
  size_t idx;

  if (state == NULL)
    return 0;

  return find_range_index (state, packet_number, &idx);
}

size_t
SocketQUICAck_range_count (const SocketQUICAckState_T state)
{
  if (state == NULL)
    return 0;
  return state->range_count;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

void
SocketQUICAck_prune (SocketQUICAckState_T state, uint64_t oldest_to_keep,
                      size_t *removed_count)
{
  size_t kept;
  size_t removed;

  if (state == NULL)
    {
      if (removed_count)
        *removed_count = 0;
      return;
    }

  removed = 0;
  kept = 0;

  /* Ranges are sorted descending, so prune from the end */
  for (size_t i = 0; i < state->range_count; i++)
    {
      if (state->ranges[i].start >= oldest_to_keep)
        {
          /* Keep this range */
          if (state->ranges[i].end < oldest_to_keep)
            {
              /* Truncate range */
              state->ranges[i].end = oldest_to_keep;
            }
          state->ranges[kept++] = state->ranges[i];
        }
      else
        {
          removed++;
        }
    }

  state->range_count = kept;

  if (removed_count)
    *removed_count = removed;
}

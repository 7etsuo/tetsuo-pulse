/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICPMTU.c - QUIC Path MTU Discovery Implementation
 *
 * Implements Datagram Packetization Layer Path MTU Discovery (DPLPMTUD)
 * per RFC 9000 Section 14 and RFC 8899.
 *
 * Key aspects:
 * - Initial packet padding to 1200 bytes (Section 14.1)
 * - DPLPMTUD state machine for finding maximum MTU (Section 14.3)
 * - ICMP validation (ignores claims < 1200 bytes)
 * - Probe loss does NOT trigger congestion response
 */

#include "quic/SocketQUICPMTU.h"
#include "quic/SocketQUICConstants.h"
#include <assert.h>
#include <string.h>

/* ============================================================================
 * Result String Table
 * ============================================================================
 */

static const char *result_strings[] = {
  [QUIC_PMTU_OK] = "OK",
  [QUIC_PMTU_ERROR_NULL] = "NULL pointer argument",
  [QUIC_PMTU_ERROR_SIZE] = "Invalid size (< 1200 bytes)",
  [QUIC_PMTU_ERROR_BUFFER] = "Buffer too small for padding",
  [QUIC_PMTU_ERROR_STATE] = "Invalid state for operation",
  [QUIC_PMTU_ERROR_PROBE_LIMIT] = "Too many probes in flight",
  [QUIC_PMTU_ERROR_ARENA] = "Arena allocation failed"
};

DEFINE_RESULT_STRING_FUNC (SocketQUICPMTU, QUIC_PMTU_ERROR_ARENA)

/* ============================================================================
 * PMTU Context Management
 * ============================================================================
 */

SocketQUICPMTU_T
SocketQUICPMTU_new (Arena_T arena, size_t initial_pmtu, size_t max_pmtu)
{
  SocketQUICPMTU_T pmtu;

  assert (arena);

  /* Validate MTU bounds */
  if (initial_pmtu < QUIC_MIN_PMTU)
    initial_pmtu = QUIC_DEFAULT_INITIAL_PMTU;
  if (max_pmtu < initial_pmtu)
    max_pmtu = QUIC_MAX_PMTU;

  /* Allocate context */
  pmtu = Arena_alloc (arena, sizeof (*pmtu), __FILE__, __LINE__);
  if (!pmtu)
    return NULL;

  memset (pmtu, 0, sizeof (*pmtu));

  /* Initialize state */
  pmtu->arena = arena;
  pmtu->state = QUIC_PMTU_STATE_INIT;
  pmtu->current_pmtu = initial_pmtu;
  pmtu->target_pmtu = initial_pmtu;
  pmtu->max_pmtu = max_pmtu;
  pmtu->probes_in_flight = 0;
  pmtu->probes = NULL;

  return pmtu;
}

void
SocketQUICPMTU_free (SocketQUICPMTU_T *pmtu)
{
  assert (pmtu);
  assert (*pmtu);

  /* Clear state (memory is arena-allocated) */
  (*pmtu)->probes = NULL;
  (*pmtu)->probes_in_flight = 0;
  *pmtu = NULL;
}

/* ============================================================================
 * Initial Packet Padding (RFC 9000 Section 14.1)
 * ============================================================================
 */

SocketQUICPMTU_Result
SocketQUICPMTU_pad_initial (uint8_t *packet, size_t *len, size_t max_len)
{
  size_t current_len;
  size_t padding_needed;

  if (!packet || !len)
    return QUIC_PMTU_ERROR_NULL;

  current_len = *len;

  /* Already meets minimum size */
  if (current_len >= QUIC_MIN_INITIAL_PACKET_SIZE)
    return QUIC_PMTU_OK;

  /* Check buffer has space */
  if (max_len < QUIC_MIN_INITIAL_PACKET_SIZE)
    return QUIC_PMTU_ERROR_BUFFER;

  /* Pad with PADDING frames (0x00) to reach 1200 bytes */
  padding_needed = QUIC_MIN_INITIAL_PACKET_SIZE - current_len;
  memset (packet + current_len, 0x00, padding_needed);
  *len = QUIC_MIN_INITIAL_PACKET_SIZE;

  return QUIC_PMTU_OK;
}

SocketQUICPMTU_Result
SocketQUICPMTU_validate_initial_size (size_t packet_len)
{
  /* RFC 9000 Section 14.1: Server MUST discard Initial < 1200 bytes */
  if (packet_len < QUIC_MIN_INITIAL_PACKET_SIZE)
    return QUIC_PMTU_ERROR_SIZE;

  return QUIC_PMTU_OK;
}

/* ============================================================================
 * PMTU Discovery State Machine (RFC 8899)
 * ============================================================================
 */

SocketQUICPMTU_Result
SocketQUICPMTU_start_discovery (SocketQUICPMTU_T pmtu)
{
  assert (pmtu);

  /* Can only start from INIT state */
  if (pmtu->state != QUIC_PMTU_STATE_INIT)
    return QUIC_PMTU_ERROR_STATE;

  /* Transition to SEARCHING */
  pmtu->state = QUIC_PMTU_STATE_SEARCHING;

  /* Start with current PMTU + increment as initial probe target */
  pmtu->target_pmtu = pmtu->current_pmtu + QUIC_PMTU_PROBE_INCREMENT;
  if (pmtu->target_pmtu > pmtu->max_pmtu)
    pmtu->target_pmtu = pmtu->max_pmtu;

  return QUIC_PMTU_OK;
}

SocketQUICPMTU_Result
SocketQUICPMTU_get_next_probe_size (SocketQUICPMTU_T pmtu, size_t *size_out)
{
  assert (pmtu);
  assert (size_out);

  if (pmtu->state != QUIC_PMTU_STATE_SEARCHING)
    return QUIC_PMTU_ERROR_STATE;

  if (pmtu->probes_in_flight >= QUIC_MAX_PMTU_PROBES_IN_FLIGHT)
    return QUIC_PMTU_ERROR_PROBE_LIMIT;

  *size_out = pmtu->target_pmtu;
  return QUIC_PMTU_OK;
}

/* ============================================================================
 * Probe Tracking
 * ============================================================================
 */

SocketQUICPMTU_Result
SocketQUICPMTU_send_probe (SocketQUICPMTU_T pmtu, uint64_t packet_number,
                            size_t size, uint64_t sent_time_ms)
{
  SocketQUICPMTU_Probe_T *probe;

  assert (pmtu);

  if (pmtu->state != QUIC_PMTU_STATE_SEARCHING)
    return QUIC_PMTU_ERROR_STATE;

  if (pmtu->probes_in_flight >= QUIC_MAX_PMTU_PROBES_IN_FLIGHT)
    return QUIC_PMTU_ERROR_PROBE_LIMIT;

  /* Allocate probe structure */
  probe = Arena_alloc (pmtu->arena, sizeof (*probe), __FILE__, __LINE__);
  if (!probe)
    return QUIC_PMTU_ERROR_ARENA;

  /* Initialize probe */
  probe->packet_number = packet_number;
  probe->size = size;
  probe->sent_time_ms = sent_time_ms;

  /* Add to linked list */
  probe->next = pmtu->probes;
  pmtu->probes = probe;
  pmtu->probes_in_flight++;

  return QUIC_PMTU_OK;
}

static SocketQUICPMTU_Probe_T *
find_and_remove_probe (SocketQUICPMTU_T pmtu, uint64_t packet_number)
{
  SocketQUICPMTU_Probe_T *probe, *prev;

  assert (pmtu);

  prev = NULL;
  for (probe = pmtu->probes; probe; probe = probe->next)
    {
      if (probe->packet_number == packet_number)
        {
          /* Remove from list */
          if (prev)
            prev->next = probe->next;
          else
            pmtu->probes = probe->next;

          pmtu->probes_in_flight--;
          return probe;
        }
      prev = probe;
    }

  return NULL;
}

SocketQUICPMTU_Result
SocketQUICPMTU_probe_acked (SocketQUICPMTU_T pmtu, uint64_t packet_number)
{
  SocketQUICPMTU_Probe_T *probe;

  assert (pmtu);

  /* Find and remove probe */
  probe = find_and_remove_probe (pmtu, packet_number);
  if (!probe)
    return QUIC_PMTU_OK; /* Not a probe packet */

  /* Probe succeeded - update current PMTU */
  if (probe->size > pmtu->current_pmtu)
    pmtu->current_pmtu = probe->size;

  /* Check if we've reached max PMTU */
  if (pmtu->current_pmtu >= pmtu->max_pmtu)
    {
      pmtu->state = QUIC_PMTU_STATE_COMPLETE;
      return QUIC_PMTU_OK;
    }

  /* Prepare next probe (binary search approach) */
  if (pmtu->state == QUIC_PMTU_STATE_SEARCHING)
    {
      size_t next_target = pmtu->current_pmtu + QUIC_PMTU_PROBE_INCREMENT;
      if (next_target > pmtu->max_pmtu)
        next_target = pmtu->max_pmtu;

      pmtu->target_pmtu = next_target;

      /* If we can't probe higher, we're done */
      if (pmtu->target_pmtu == pmtu->current_pmtu)
        pmtu->state = QUIC_PMTU_STATE_COMPLETE;
    }

  return QUIC_PMTU_OK;
}

static void
update_pmtu_on_probe_failure (SocketQUICPMTU_T pmtu,
                               SocketQUICPMTU_Probe_T *probe)
{
  assert (pmtu);
  assert (probe);

  /* Probe lost - do NOT update current_pmtu */
  /* RFC 9000 Section 14.3: Probe loss does NOT trigger congestion response */

  /* Try a smaller probe (halfway between current and failed) */
  if (pmtu->state == QUIC_PMTU_STATE_SEARCHING)
    {
      size_t failed_size = probe->size;
      size_t new_target = pmtu->current_pmtu
                          + (failed_size - pmtu->current_pmtu) / 2;

      if (new_target > pmtu->current_pmtu)
        pmtu->target_pmtu = new_target;
      else
        {
          /* Can't probe any smaller increment - done */
          pmtu->state = QUIC_PMTU_STATE_COMPLETE;
        }
    }
}

SocketQUICPMTU_Result
SocketQUICPMTU_probe_lost (SocketQUICPMTU_T pmtu, uint64_t packet_number)
{
  SocketQUICPMTU_Probe_T *probe;

  assert (pmtu);

  /* Find and remove probe */
  probe = find_and_remove_probe (pmtu, packet_number);
  if (!probe)
    return QUIC_PMTU_OK; /* Not a probe packet */

  /* Update state machine based on probe failure */
  update_pmtu_on_probe_failure (pmtu, probe);

  return QUIC_PMTU_OK;
}

/* ============================================================================
 * ICMP Processing (RFC 9000 Section 14.2)
 * ============================================================================
 */

SocketQUICPMTU_Result
SocketQUICPMTU_process_icmp (SocketQUICPMTU_T pmtu, size_t icmp_mtu)
{
  assert (pmtu);

  /* RFC 9000 Section 14.2: Ignore ICMP claims < 1200 bytes */
  if (icmp_mtu < QUIC_MIN_PMTU)
    return QUIC_PMTU_OK;

  /* Only reduce PMTU if ICMP reports smaller value */
  if (icmp_mtu < pmtu->current_pmtu)
    {
      pmtu->current_pmtu = icmp_mtu;

      /* Update target if it's now too high */
      if (pmtu->target_pmtu > icmp_mtu)
        pmtu->target_pmtu = icmp_mtu;
    }

  return QUIC_PMTU_OK;
}

/* ============================================================================
 * Query Functions
 * ============================================================================
 */

size_t
SocketQUICPMTU_get_current (SocketQUICPMTU_T pmtu)
{
  assert (pmtu);
  return pmtu->current_pmtu;
}

SocketQUICPMTU_State
SocketQUICPMTU_get_state (SocketQUICPMTU_T pmtu)
{
  assert (pmtu);
  return pmtu->state;
}

/* ============================================================================
 * Timeout Handling
 * ============================================================================
 */

SocketQUICPMTU_Result
SocketQUICPMTU_check_timeouts (SocketQUICPMTU_T pmtu, uint64_t current_time_ms)
{
  SocketQUICPMTU_Probe_T *probe, *next;
  SocketQUICPMTU_Probe_T **prev_ptr;

  assert (pmtu);

  prev_ptr = &pmtu->probes;
  probe = pmtu->probes;

  while (probe)
    {
      next = probe->next;

      /* Check if probe has timed out */
      if (current_time_ms - probe->sent_time_ms > QUIC_PMTU_PROBE_TIMEOUT_MS)
        {
          /* Remove from list */
          *prev_ptr = next;
          pmtu->probes_in_flight--;

          /* Update state machine based on probe failure */
          update_pmtu_on_probe_failure (pmtu, probe);
        }
      else
        {
          prev_ptr = &probe->next;
        }

      probe = next;
    }

  return QUIC_PMTU_OK;
}

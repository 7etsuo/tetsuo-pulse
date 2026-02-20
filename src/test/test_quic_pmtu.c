/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_pmtu.c - QUIC Path MTU Discovery unit tests
 *
 * Tests PMTU discovery per RFC 9000 Section 14:
 * - Initial packet padding (Section 14.1)
 * - DPLPMTUD state machine (Section 14.3)
 * - ICMP message validation (Section 14.2)
 * - Probe acknowledgment and loss handling
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICPMTU.h"
#include "core/Arena.h"
#include "test/Test.h"

TEST (quic_pmtu_pad_initial_small_packet)
{
  uint8_t packet[2048];
  size_t len = 950;
  SocketQUICPMTU_Result result;

  /* Pad small packet to 1200 bytes */
  result = SocketQUICPMTU_pad_initial (packet, &len, sizeof (packet));

  ASSERT_EQ (result, QUIC_PMTU_OK);
  ASSERT_EQ (len, QUIC_MIN_INITIAL_PACKET_SIZE);

  /* Verify padding bytes are 0x00 (PADDING frames) */
  for (size_t i = 950; i < 1200; i++)
    {
      ASSERT_EQ (packet[i], 0x00);
    }
}

TEST (quic_pmtu_pad_initial_already_large)
{
  uint8_t packet[2048];
  size_t len = 1300;
  size_t original_len = len;
  SocketQUICPMTU_Result result;

  /* Packet already meets minimum - no padding needed */
  result = SocketQUICPMTU_pad_initial (packet, &len, sizeof (packet));

  ASSERT_EQ (result, QUIC_PMTU_OK);
  ASSERT_EQ (len, original_len);
}

TEST (quic_pmtu_pad_initial_buffer_too_small)
{
  uint8_t packet[1000]; /* Too small for 1200 bytes */
  size_t len = 950;
  SocketQUICPMTU_Result result;

  result = SocketQUICPMTU_pad_initial (packet, &len, sizeof (packet));

  ASSERT_EQ (result, QUIC_PMTU_ERROR_BUFFER);
}

TEST (quic_pmtu_pad_initial_null_args)
{
  uint8_t packet[2048];
  size_t len = 950;
  SocketQUICPMTU_Result result;

  result = SocketQUICPMTU_pad_initial (NULL, &len, sizeof (packet));
  ASSERT_EQ (result, QUIC_PMTU_ERROR_NULL);

  result = SocketQUICPMTU_pad_initial (packet, NULL, sizeof (packet));
  ASSERT_EQ (result, QUIC_PMTU_ERROR_NULL);
}

TEST (quic_pmtu_validate_initial_size_valid)
{
  SocketQUICPMTU_Result result;

  result = SocketQUICPMTU_validate_initial_size (1200);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  result = SocketQUICPMTU_validate_initial_size (1500);
  ASSERT_EQ (result, QUIC_PMTU_OK);
}

TEST (quic_pmtu_validate_initial_size_too_small)
{
  SocketQUICPMTU_Result result;

  result = SocketQUICPMTU_validate_initial_size (1199);
  ASSERT_EQ (result, QUIC_PMTU_ERROR_SIZE);

  result = SocketQUICPMTU_validate_initial_size (500);
  ASSERT_EQ (result, QUIC_PMTU_ERROR_SIZE);
}

TEST (quic_pmtu_new_default)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;

  pmtu = SocketQUICPMTU_new (arena, QUIC_DEFAULT_INITIAL_PMTU, QUIC_MAX_PMTU);

  ASSERT_NE (pmtu, NULL);
  ASSERT_EQ (SocketQUICPMTU_get_current (pmtu), QUIC_DEFAULT_INITIAL_PMTU);
  ASSERT_EQ (SocketQUICPMTU_get_state (pmtu), QUIC_PMTU_STATE_INIT);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_new_custom)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;

  pmtu = SocketQUICPMTU_new (arena, 1280, 1500);

  ASSERT_NE (pmtu, NULL);
  ASSERT_EQ (SocketQUICPMTU_get_current (pmtu), 1280);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_new_invalid_bounds)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;

  /* Initial PMTU too small - should use default */
  pmtu = SocketQUICPMTU_new (arena, 1000, 1500);
  ASSERT_EQ (SocketQUICPMTU_get_current (pmtu), QUIC_DEFAULT_INITIAL_PMTU);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_start_discovery)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;

  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);

  result = SocketQUICPMTU_start_discovery (pmtu);

  ASSERT_EQ (result, QUIC_PMTU_OK);
  ASSERT_EQ (SocketQUICPMTU_get_state (pmtu), QUIC_PMTU_STATE_SEARCHING);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_get_next_probe_size)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;
  size_t probe_size;

  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  SocketQUICPMTU_start_discovery (pmtu);

  result = SocketQUICPMTU_get_next_probe_size (pmtu, &probe_size);

  ASSERT_EQ (result, QUIC_PMTU_OK);
  ASSERT (probe_size > 1200 && probe_size <= 1500);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_probe_acked_success)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;
  size_t probe_size;
  size_t initial_pmtu;

  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  initial_pmtu = SocketQUICPMTU_get_current (pmtu);

  SocketQUICPMTU_start_discovery (pmtu);
  SocketQUICPMTU_get_next_probe_size (pmtu, &probe_size);

  /* Send probe */
  result = SocketQUICPMTU_send_probe (pmtu, 100, probe_size, 1000);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /* ACK probe */
  result = SocketQUICPMTU_probe_acked (pmtu, 100);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /* Current PMTU should be updated */
  ASSERT (SocketQUICPMTU_get_current (pmtu) > initial_pmtu);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_probe_lost)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;
  size_t probe_size;
  size_t initial_pmtu;

  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  initial_pmtu = SocketQUICPMTU_get_current (pmtu);

  SocketQUICPMTU_start_discovery (pmtu);
  SocketQUICPMTU_get_next_probe_size (pmtu, &probe_size);

  /* Send probe */
  result = SocketQUICPMTU_send_probe (pmtu, 100, probe_size, 1000);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /* Mark probe as lost */
  result = SocketQUICPMTU_probe_lost (pmtu, 100);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /* Current PMTU should NOT change */
  ASSERT_EQ (SocketQUICPMTU_get_current (pmtu), initial_pmtu);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_process_icmp_valid)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;

  pmtu = SocketQUICPMTU_new (arena, 1400, 1500);

  /* Process ICMP with smaller MTU */
  result = SocketQUICPMTU_process_icmp (pmtu, 1300);

  ASSERT_EQ (result, QUIC_PMTU_OK);
  ASSERT_EQ (SocketQUICPMTU_get_current (pmtu), 1300);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_process_icmp_too_small)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;
  size_t initial_pmtu;

  pmtu = SocketQUICPMTU_new (arena, 1400, 1500);
  initial_pmtu = SocketQUICPMTU_get_current (pmtu);

  /* RFC 9000 Section 14.2: Ignore ICMP claims < 1200 bytes */
  result = SocketQUICPMTU_process_icmp (pmtu, 1000);

  ASSERT_EQ (result, QUIC_PMTU_OK);
  ASSERT_EQ (SocketQUICPMTU_get_current (pmtu), initial_pmtu);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_process_icmp_larger)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;
  size_t initial_pmtu;

  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  initial_pmtu = SocketQUICPMTU_get_current (pmtu);

  /* ICMP reports larger MTU - should not increase PMTU */
  result = SocketQUICPMTU_process_icmp (pmtu, 1400);

  ASSERT_EQ (result, QUIC_PMTU_OK);
  ASSERT_EQ (SocketQUICPMTU_get_current (pmtu), initial_pmtu);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_check_timeouts)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;
  size_t probe_size;

  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  SocketQUICPMTU_start_discovery (pmtu);
  SocketQUICPMTU_get_next_probe_size (pmtu, &probe_size);

  /* Send probe at time 1000ms */
  result = SocketQUICPMTU_send_probe (pmtu, 100, probe_size, 1000);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /* Check timeouts at 2000ms - should not timeout yet */
  result = SocketQUICPMTU_check_timeouts (pmtu, 2000);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /* Check timeouts at 5000ms - should timeout (3 second timeout) */
  result = SocketQUICPMTU_check_timeouts (pmtu, 5000);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_timeout_updates_state_machine)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;
  size_t probe_size;
  size_t target_before_timeout;
  size_t target_after_timeout;

  /* Initialize with 1200 byte PMTU, max 1500 */
  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  SocketQUICPMTU_start_discovery (pmtu);

  /* Get probe size (should be 1300 = 1200 + 100) */
  SocketQUICPMTU_get_next_probe_size (pmtu, &probe_size);
  ASSERT_EQ (probe_size, 1300);
  target_before_timeout = probe_size;

  /* Send probe at time 1000ms */
  result = SocketQUICPMTU_send_probe (pmtu, 100, probe_size, 1000);
  ASSERT_EQ (result, QUIC_PMTU_OK);
  ASSERT_EQ (SocketQUICPMTU_get_state (pmtu), QUIC_PMTU_STATE_SEARCHING);

  /* Trigger timeout at 5000ms (> 3000ms timeout) */
  result = SocketQUICPMTU_check_timeouts (pmtu, 5000);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /*
   * CRITICAL: State machine MUST be updated on timeout
   * Before the fix (issue #789), state machine was NOT updated
   * because probe was removed before calling update logic
   */

  /* Get next probe size - should be adjusted based on failure */
  result = SocketQUICPMTU_get_next_probe_size (pmtu, &target_after_timeout);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /*
   * Target should be halfway between current (1200) and failed (1300)
   * new_target = 1200 + (1300 - 1200) / 2 = 1200 + 50 = 1250
   */
  ASSERT_EQ (target_after_timeout, 1250);
  ASSERT (target_after_timeout < target_before_timeout);
  ASSERT (target_after_timeout > 1200);

  /* State should still be SEARCHING (not stuck) */
  ASSERT_EQ (SocketQUICPMTU_get_state (pmtu), QUIC_PMTU_STATE_SEARCHING);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_timeout_completes_when_no_increment)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;

  /* Start with very narrow range to force completion */
  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  SocketQUICPMTU_start_discovery (pmtu);

  /* Send probe just 1 byte larger than current */
  result = SocketQUICPMTU_send_probe (pmtu, 100, 1201, 1000);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /* Trigger timeout */
  result = SocketQUICPMTU_check_timeouts (pmtu, 5000);
  ASSERT_EQ (result, QUIC_PMTU_OK);

  /*
   * new_target = 1200 + (1201 - 1200) / 2 = 1200 + 0 = 1200
   * Since new_target == current_pmtu, state should transition to COMPLETE
   */
  ASSERT_EQ (SocketQUICPMTU_get_state (pmtu), QUIC_PMTU_STATE_COMPLETE);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_probe_limit)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;
  size_t probe_size;

  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  SocketQUICPMTU_start_discovery (pmtu);
  SocketQUICPMTU_get_next_probe_size (pmtu, &probe_size);

  /* Send maximum number of probes */
  for (int i = 0; i < QUIC_MAX_PMTU_PROBES_IN_FLIGHT; i++)
    {
      result = SocketQUICPMTU_send_probe (pmtu, 100 + i, probe_size, 1000);
      ASSERT_EQ (result, QUIC_PMTU_OK);
    }

  /* Try to send one more - should fail */
  result = SocketQUICPMTU_send_probe (pmtu, 200, probe_size, 1000);
  ASSERT_EQ (result, QUIC_PMTU_ERROR_PROBE_LIMIT);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_result_strings)
{
  const char *str;

  str = SocketQUICPMTU_result_string (QUIC_PMTU_OK);
  ASSERT_NE (str, NULL);

  str = SocketQUICPMTU_result_string (QUIC_PMTU_ERROR_NULL);
  ASSERT_NE (str, NULL);

  str = SocketQUICPMTU_result_string (QUIC_PMTU_ERROR_SIZE);
  ASSERT_NE (str, NULL);

  str = SocketQUICPMTU_result_string (999);
  ASSERT_NE (str, NULL);
}

TEST (quic_pmtu_send_probe_size_underflow_protection)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;

  /* Initialize with 1200 byte PMTU */
  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  SocketQUICPMTU_start_discovery (pmtu);

  /* Attempt to send probe smaller than current PMTU (invalid) */
  result = SocketQUICPMTU_send_probe (pmtu, 100, 1100, 1000);

  /* Should reject with ERROR_SIZE to prevent integer underflow */
  ASSERT_EQ (result, QUIC_PMTU_ERROR_SIZE);

  /* Verify PMTU state is not corrupted */
  ASSERT_EQ (SocketQUICPMTU_get_current (pmtu), 1200);
  ASSERT_EQ (SocketQUICPMTU_get_state (pmtu), QUIC_PMTU_STATE_SEARCHING);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_send_probe_exact_current_pmtu)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;

  /* Initialize with 1200 byte PMTU */
  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  SocketQUICPMTU_start_discovery (pmtu);

  /* Attempt to send probe exactly equal to current PMTU (edge case) */
  result = SocketQUICPMTU_send_probe (pmtu, 100, 1200, 1000);

  /* Should reject - probe must be larger to discover higher PMTU */
  ASSERT_EQ (result, QUIC_PMTU_ERROR_SIZE);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_send_probe_valid_larger_size)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;

  /* Initialize with 1200 byte PMTU */
  pmtu = SocketQUICPMTU_new (arena, 1200, 1500);
  SocketQUICPMTU_start_discovery (pmtu);

  /* Send probe larger than current PMTU (valid) */
  result = SocketQUICPMTU_send_probe (pmtu, 100, 1300, 1000);

  /* Should succeed */
  ASSERT_EQ (result, QUIC_PMTU_OK);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

TEST (quic_pmtu_send_probe_minimum_boundary)
{
  Arena_T arena = Arena_new ();
  SocketQUICPMTU_T pmtu;
  SocketQUICPMTU_Result result;

  /* Initialize with minimum PMTU */
  pmtu = SocketQUICPMTU_new (arena, QUIC_MIN_PMTU, 1500);
  SocketQUICPMTU_start_discovery (pmtu);

  /* Attempt to send probe at minimum - 1 (invalid) */
  result = SocketQUICPMTU_send_probe (pmtu, 100, QUIC_MIN_PMTU - 1, 1000);

  /* Should reject */
  ASSERT_EQ (result, QUIC_PMTU_ERROR_SIZE);

  /* Send valid probe at minimum + 1 */
  result = SocketQUICPMTU_send_probe (pmtu, 101, QUIC_MIN_PMTU + 1, 1000);

  /* Should succeed */
  ASSERT_EQ (result, QUIC_PMTU_OK);

  SocketQUICPMTU_free (&pmtu);
  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

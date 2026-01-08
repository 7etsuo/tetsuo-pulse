/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_config.c
 * @brief Unit tests for QPACK Configuration (RFC 9204 Section 5)
 *
 * Tests the QPACK settings and configuration management including:
 * - Settings defaults and validation
 * - Local/peer settings management
 * - 0-RTT settings storage and validation
 */

#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * SETTINGS CONSTANTS TESTS
 * ============================================================================
 */

TEST (qpack_config_settings_constants)
{
  /* RFC 9204 Section 5: Verify SETTINGS identifiers */
  ASSERT_EQ (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0x01);
  ASSERT_EQ (SETTINGS_QPACK_BLOCKED_STREAMS, 0x07);
}

/* ============================================================================
 * SETTINGS DEFAULTS TESTS
 * ============================================================================
 */

TEST (qpack_config_settings_defaults_basic)
{
  SocketQPACK_Settings settings;

  /* Initialize with non-zero values */
  settings.max_table_capacity = 12345;
  settings.blocked_streams = 67890;

  /* Apply defaults */
  ASSERT_EQ (SocketQPACK_settings_defaults (&settings), QPACK_OK);

  /* RFC 9204 Section 5: Both settings default to 0 */
  ASSERT_EQ (settings.max_table_capacity, 0);
  ASSERT_EQ (settings.blocked_streams, 0);
}

TEST (qpack_config_settings_defaults_null)
{
  ASSERT_EQ (SocketQPACK_settings_defaults (NULL), QPACK_ERR_NULL_PARAM);
}

/* ============================================================================
 * SETTINGS VALIDATION TESTS
 * ============================================================================
 */

TEST (qpack_config_settings_validate_valid)
{
  SocketQPACK_Settings settings;

  /* Zero values (defaults) are valid */
  settings.max_table_capacity = 0;
  settings.blocked_streams = 0;
  ASSERT_EQ (SocketQPACK_settings_validate (&settings), QPACK_OK);

  /* Typical values are valid */
  settings.max_table_capacity = 4096;
  settings.blocked_streams = 100;
  ASSERT_EQ (SocketQPACK_settings_validate (&settings), QPACK_OK);

  /* Large values are valid (RFC doesn't specify upper limit) */
  settings.max_table_capacity = UINT64_MAX;
  settings.blocked_streams = UINT64_MAX;
  ASSERT_EQ (SocketQPACK_settings_validate (&settings), QPACK_OK);
}

TEST (qpack_config_settings_validate_null)
{
  ASSERT_EQ (SocketQPACK_settings_validate (NULL), QPACK_ERR_NULL_PARAM);
}

/* ============================================================================
 * CONFIG CREATION TESTS
 * ============================================================================
 */

TEST (qpack_config_new_basic)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);

  ASSERT_NOT_NULL (config);

  /* Verify initial state */
  ASSERT (!SocketQPACK_Config_has_peer_settings (config));

  Arena_dispose (&arena);
}

TEST (qpack_config_new_null_arena)
{
  SocketQPACK_Config_T config = SocketQPACK_Config_new (NULL);
  ASSERT_NULL (config);
}

TEST (qpack_config_new_has_defaults)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings settings;

  ASSERT_NOT_NULL (config);

  /* Local settings should be defaults (0, 0) */
  ASSERT_EQ (SocketQPACK_Config_get_local (config, &settings), QPACK_OK);
  ASSERT_EQ (settings.max_table_capacity, 0);
  ASSERT_EQ (settings.blocked_streams, 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * LOCAL SETTINGS TESTS
 * ============================================================================
 */

TEST (qpack_config_set_get_local_roundtrip)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings in, out;

  ASSERT_NOT_NULL (config);

  /* Set local settings */
  in.max_table_capacity = 8192;
  in.blocked_streams = 50;
  ASSERT_EQ (SocketQPACK_Config_set_local (config, &in), QPACK_OK);

  /* Get local settings */
  ASSERT_EQ (SocketQPACK_Config_get_local (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, 8192);
  ASSERT_EQ (out.blocked_streams, 50);

  Arena_dispose (&arena);
}

TEST (qpack_config_set_local_null_config)
{
  SocketQPACK_Settings settings = { 0, 0 };
  ASSERT_EQ (SocketQPACK_Config_set_local (NULL, &settings),
             QPACK_ERR_NULL_PARAM);
}

TEST (qpack_config_set_local_null_settings)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);

  ASSERT_EQ (SocketQPACK_Config_set_local (config, NULL), QPACK_ERR_NULL_PARAM);

  Arena_dispose (&arena);
}

TEST (qpack_config_get_local_null_config)
{
  SocketQPACK_Settings settings;
  ASSERT_EQ (SocketQPACK_Config_get_local (NULL, &settings),
             QPACK_ERR_NULL_PARAM);
}

TEST (qpack_config_get_local_null_settings)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);

  ASSERT_EQ (SocketQPACK_Config_get_local (config, NULL), QPACK_ERR_NULL_PARAM);

  Arena_dispose (&arena);
}

/* ============================================================================
 * PEER SETTINGS TESTS
 * ============================================================================
 */

TEST (qpack_config_apply_peer_basic)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings peer_settings, out;

  ASSERT_NOT_NULL (config);

  /* Initially no peer settings */
  ASSERT (!SocketQPACK_Config_has_peer_settings (config));

  /* Apply peer settings */
  peer_settings.max_table_capacity = 16384;
  peer_settings.blocked_streams = 200;
  ASSERT_EQ (SocketQPACK_Config_apply_peer (config, &peer_settings), QPACK_OK);

  /* Now we have peer settings */
  ASSERT (SocketQPACK_Config_has_peer_settings (config));

  /* Get peer settings */
  ASSERT_EQ (SocketQPACK_Config_get_peer (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, 16384);
  ASSERT_EQ (out.blocked_streams, 200);

  Arena_dispose (&arena);
}

TEST (qpack_config_get_peer_before_apply)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings out;

  ASSERT_NOT_NULL (config);

  /* Getting peer settings before apply_peer should fail */
  ASSERT_EQ (SocketQPACK_Config_get_peer (config, &out), QPACK_ERR_INTERNAL);

  Arena_dispose (&arena);
}

TEST (qpack_config_apply_peer_null_config)
{
  SocketQPACK_Settings settings = { 0, 0 };
  ASSERT_EQ (SocketQPACK_Config_apply_peer (NULL, &settings),
             QPACK_ERR_NULL_PARAM);
}

TEST (qpack_config_apply_peer_null_settings)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);

  ASSERT_EQ (SocketQPACK_Config_apply_peer (config, NULL),
             QPACK_ERR_NULL_PARAM);

  Arena_dispose (&arena);
}

TEST (qpack_config_get_peer_null_config)
{
  SocketQPACK_Settings settings;
  ASSERT_EQ (SocketQPACK_Config_get_peer (NULL, &settings),
             QPACK_ERR_NULL_PARAM);
}

TEST (qpack_config_get_peer_null_settings)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings peer = { 100, 10 };

  /* Apply peer settings first */
  ASSERT_EQ (SocketQPACK_Config_apply_peer (config, &peer), QPACK_OK);

  /* Get with NULL output should fail */
  ASSERT_EQ (SocketQPACK_Config_get_peer (config, NULL), QPACK_ERR_NULL_PARAM);

  Arena_dispose (&arena);
}

TEST (qpack_config_has_peer_null)
{
  ASSERT (!SocketQPACK_Config_has_peer_settings (NULL));
}

/* ============================================================================
 * 0-RTT SETTINGS TESTS (RFC 9204 Section 3.2.3)
 * ============================================================================
 */

TEST (qpack_config_0rtt_store_get_roundtrip)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings in, out;

  ASSERT_NOT_NULL (config);

  /* Store 0-RTT settings */
  in.max_table_capacity = 4096;
  in.blocked_streams = 100;
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &in), QPACK_OK);

  /* Retrieve 0-RTT settings */
  ASSERT_EQ (SocketQPACK_Config_get_0rtt (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, 4096);
  ASSERT_EQ (out.blocked_streams, 100);

  Arena_dispose (&arena);
}

TEST (qpack_config_0rtt_get_before_store)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings out;

  ASSERT_NOT_NULL (config);

  /* Getting 0-RTT settings before store should fail */
  ASSERT_EQ (SocketQPACK_Config_get_0rtt (config, &out), QPACK_ERR_INTERNAL);

  Arena_dispose (&arena);
}

TEST (qpack_config_0rtt_store_null_config)
{
  SocketQPACK_Settings settings = { 0, 0 };
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (NULL, &settings),
             QPACK_ERR_NULL_PARAM);
}

TEST (qpack_config_0rtt_store_null_settings)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);

  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, NULL),
             QPACK_ERR_NULL_PARAM);

  Arena_dispose (&arena);
}

TEST (qpack_config_0rtt_get_null_config)
{
  SocketQPACK_Settings settings;
  ASSERT_EQ (SocketQPACK_Config_get_0rtt (NULL, &settings),
             QPACK_ERR_NULL_PARAM);
}

TEST (qpack_config_0rtt_get_null_settings)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings stored = { 100, 10 };

  /* Store first */
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &stored), QPACK_OK);

  /* Get with NULL output should fail */
  ASSERT_EQ (SocketQPACK_Config_get_0rtt (config, NULL), QPACK_ERR_NULL_PARAM);

  Arena_dispose (&arena);
}

/* ============================================================================
 * 0-RTT VALIDATION TESTS (RFC 9204 Section 3.2.3)
 * ============================================================================
 */

TEST (qpack_config_0rtt_validate_no_stored)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings peer = { 4096, 100 };

  ASSERT_NOT_NULL (config);

  /* No 0-RTT stored, validation should pass */
  ASSERT_EQ (SocketQPACK_Config_validate_0rtt (config, &peer), QPACK_OK);

  Arena_dispose (&arena);
}

TEST (qpack_config_0rtt_validate_zero_capacity_any_peer)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings stored = { 0, 100 };
  SocketQPACK_Settings peer = { 8192, 50 };

  ASSERT_NOT_NULL (config);

  /* Store 0-RTT with max_table_capacity = 0 */
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &stored), QPACK_OK);

  /* RFC 9204 Section 3.2.3: When 0-RTT capacity is 0, peer MAY set any value */
  ASSERT_EQ (SocketQPACK_Config_validate_0rtt (config, &peer), QPACK_OK);

  Arena_dispose (&arena);
}

TEST (qpack_config_0rtt_validate_nonzero_capacity_match)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings stored = { 4096, 100 };
  SocketQPACK_Settings peer
      = { 4096, 50 }; /* Same capacity, different blocked */

  ASSERT_NOT_NULL (config);

  /* Store 0-RTT with non-zero max_table_capacity */
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &stored), QPACK_OK);

  /* RFC 9204 Section 3.2.3: Peer MUST send same max_table_capacity */
  ASSERT_EQ (SocketQPACK_Config_validate_0rtt (config, &peer), QPACK_OK);

  Arena_dispose (&arena);
}

TEST (qpack_config_0rtt_validate_nonzero_capacity_mismatch)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings stored = { 4096, 100 };
  SocketQPACK_Settings peer = { 8192, 100 }; /* Different capacity */

  ASSERT_NOT_NULL (config);

  /* Store 0-RTT with non-zero max_table_capacity */
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &stored), QPACK_OK);

  /* RFC 9204 Section 3.2.3: Mismatch is a connection error */
  ASSERT_EQ (SocketQPACK_Config_validate_0rtt (config, &peer),
             QPACK_ERR_0RTT_MISMATCH);

  Arena_dispose (&arena);
}

TEST (qpack_config_0rtt_validate_nonzero_capacity_peer_zero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings stored = { 4096, 100 };
  SocketQPACK_Settings peer = { 0, 100 }; /* Peer sends 0 */

  ASSERT_NOT_NULL (config);

  /* Store 0-RTT with non-zero max_table_capacity */
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &stored), QPACK_OK);

  /* RFC 9204 Section 3.2.3: Peer sending 0 when we had non-zero is error */
  ASSERT_EQ (SocketQPACK_Config_validate_0rtt (config, &peer),
             QPACK_ERR_0RTT_MISMATCH);

  Arena_dispose (&arena);
}

TEST (qpack_config_0rtt_validate_null_config)
{
  SocketQPACK_Settings peer = { 4096, 100 };
  ASSERT_EQ (SocketQPACK_Config_validate_0rtt (NULL, &peer),
             QPACK_ERR_NULL_PARAM);
}

TEST (qpack_config_0rtt_validate_null_peer)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);

  ASSERT_EQ (SocketQPACK_Config_validate_0rtt (config, NULL),
             QPACK_ERR_NULL_PARAM);

  Arena_dispose (&arena);
}

TEST (qpack_config_has_0rtt_settings_basic)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings settings = { 4096, 100 };

  ASSERT_NOT_NULL (config);

  /* Initially no 0-RTT settings */
  ASSERT (!SocketQPACK_Config_has_0rtt_settings (config));

  /* Store 0-RTT settings */
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &settings), QPACK_OK);

  /* Now we have 0-RTT settings */
  ASSERT (SocketQPACK_Config_has_0rtt_settings (config));

  Arena_dispose (&arena);
}

TEST (qpack_config_has_0rtt_settings_null)
{
  ASSERT (!SocketQPACK_Config_has_0rtt_settings (NULL));
}

TEST (qpack_config_0rtt_overwrite)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings first = { 4096, 100 };
  SocketQPACK_Settings second = { 8192, 200 };
  SocketQPACK_Settings out;

  ASSERT_NOT_NULL (config);

  /* Store first settings */
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &first), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Config_get_0rtt (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, 4096);

  /* Overwrite with second settings */
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &second), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Config_get_0rtt (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, 8192);
  ASSERT_EQ (out.blocked_streams, 200);

  Arena_dispose (&arena);
}

TEST (qpack_config_apply_peer_update)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings first = { 4096, 50 };
  SocketQPACK_Settings second = { 8192, 100 };
  SocketQPACK_Settings out;

  ASSERT_NOT_NULL (config);

  /* Apply first peer settings */
  ASSERT_EQ (SocketQPACK_Config_apply_peer (config, &first), QPACK_OK);
  ASSERT (SocketQPACK_Config_has_peer_settings (config));
  ASSERT_EQ (SocketQPACK_Config_get_peer (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, 4096);

  /* Apply updated peer settings */
  ASSERT_EQ (SocketQPACK_Config_apply_peer (config, &second), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Config_get_peer (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, 8192);
  ASSERT_EQ (out.blocked_streams, 100);

  Arena_dispose (&arena);
}

TEST (qpack_config_boundary_values)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings settings, out;

  ASSERT_NOT_NULL (config);

  /* Test maximum uint64_t values */
  settings.max_table_capacity = UINT64_MAX;
  settings.blocked_streams = UINT64_MAX;

  ASSERT_EQ (SocketQPACK_Config_set_local (config, &settings), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Config_get_local (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, UINT64_MAX);
  ASSERT_EQ (out.blocked_streams, UINT64_MAX);

  /* Peer settings with max values should also work */
  ASSERT_EQ (SocketQPACK_Config_apply_peer (config, &settings), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Config_get_peer (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, UINT64_MAX);

  Arena_dispose (&arena);
}

/* ============================================================================
 * SETTINGS ID STRING TESTS
 * ============================================================================
 */

TEST (qpack_config_settings_id_string_known)
{
  ASSERT (strcmp (SocketQPACK_settings_id_string (
                      SETTINGS_QPACK_MAX_TABLE_CAPACITY),
                  "SETTINGS_QPACK_MAX_TABLE_CAPACITY")
          == 0);
  ASSERT (
      strcmp (SocketQPACK_settings_id_string (SETTINGS_QPACK_BLOCKED_STREAMS),
              "SETTINGS_QPACK_BLOCKED_STREAMS")
      == 0);
}

TEST (qpack_config_settings_id_string_unknown)
{
  ASSERT (strcmp (SocketQPACK_settings_id_string (0x00), "UNKNOWN") == 0);
  ASSERT (strcmp (SocketQPACK_settings_id_string (0x02), "UNKNOWN") == 0);
  ASSERT (strcmp (SocketQPACK_settings_id_string (0xFF), "UNKNOWN") == 0);
  ASSERT (strcmp (SocketQPACK_settings_id_string (UINT64_MAX), "UNKNOWN") == 0);
}

/* ============================================================================
 * INTEGRATION TESTS
 * ============================================================================
 */

TEST (qpack_config_full_negotiation_flow)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings local, peer, out;

  ASSERT_NOT_NULL (config);

  /* Step 1: Set local settings (what we'll advertise) */
  local.max_table_capacity = 8192;
  local.blocked_streams = 100;
  ASSERT_EQ (SocketQPACK_Config_set_local (config, &local), QPACK_OK);

  /* Step 2: Receive and apply peer settings */
  peer.max_table_capacity = 4096;
  peer.blocked_streams = 50;
  ASSERT_EQ (SocketQPACK_Config_apply_peer (config, &peer), QPACK_OK);

  /* Step 3: Verify both settings are available */
  ASSERT_EQ (SocketQPACK_Config_get_local (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, 8192);
  ASSERT_EQ (out.blocked_streams, 100);

  ASSERT_EQ (SocketQPACK_Config_get_peer (config, &out), QPACK_OK);
  ASSERT_EQ (out.max_table_capacity, 4096);
  ASSERT_EQ (out.blocked_streams, 50);

  ASSERT (SocketQPACK_Config_has_peer_settings (config));

  Arena_dispose (&arena);
}

TEST (qpack_config_0rtt_resumption_flow)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings session_settings, resumed, peer;

  ASSERT_NOT_NULL (config);

  /* Simulate previous connection: store settings for resumption */
  session_settings.max_table_capacity = 4096;
  session_settings.blocked_streams = 100;
  ASSERT_EQ (SocketQPACK_Config_store_for_0rtt (config, &session_settings),
             QPACK_OK);

  /* Simulate resumption: get stored settings for early data */
  ASSERT_EQ (SocketQPACK_Config_get_0rtt (config, &resumed), QPACK_OK);
  ASSERT_EQ (resumed.max_table_capacity, 4096);
  ASSERT_EQ (resumed.blocked_streams, 100);

  /* Simulate handshake complete: peer sends same capacity (valid) */
  peer.max_table_capacity = 4096;
  peer.blocked_streams = 50; /* Different blocked_streams is OK */
  ASSERT_EQ (SocketQPACK_Config_validate_0rtt (config, &peer), QPACK_OK);

  Arena_dispose (&arena);
}

TEST (qpack_config_zero_settings_disables_features)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Config_T config = SocketQPACK_Config_new (arena);
  SocketQPACK_Settings settings, out;

  ASSERT_NOT_NULL (config);

  /* RFC 9204 Section 5: Zero values disable features */
  settings.max_table_capacity = 0; /* No dynamic table */
  settings.blocked_streams = 0;    /* No blocking allowed */

  ASSERT_EQ (SocketQPACK_Config_set_local (config, &settings), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Config_get_local (config, &out), QPACK_OK);

  ASSERT_EQ (out.max_table_capacity, 0);
  ASSERT_EQ (out.blocked_streams, 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * MAIN
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

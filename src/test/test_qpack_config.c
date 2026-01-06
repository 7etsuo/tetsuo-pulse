/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_config.c
 * @brief Unit tests for QPACK Configuration (RFC 9204 Section 5).
 *
 * Tests cover:
 * - Settings identifiers match RFC (0x01, 0x07)
 * - Default settings are (0, 0) per RFC
 * - Settings validation (capacity and blocked_streams limits)
 * - Configuration creation and management
 * - Peer settings application
 * - 0-RTT settings handling
 * - Dynamic table and blocking status queries
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketQPACK.h"

/* Simple test assertion macro */
#define TEST_ASSERT(cond, msg)                                               \
  do                                                                         \
    {                                                                        \
      if (!(cond))                                                           \
        {                                                                    \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
          exit (1);                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

/* ============================================================================
 * Settings Identifier Tests
 * ============================================================================
 */

static void
test_settings_identifiers (void)
{
  printf ("  Settings identifiers match RFC 9204... ");

  /* RFC 9204 Section 5: SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01 */
  TEST_ASSERT (SETTINGS_QPACK_MAX_TABLE_CAPACITY == 0x01,
               "SETTINGS_QPACK_MAX_TABLE_CAPACITY should be 0x01");

  /* RFC 9204 Section 5: SETTINGS_QPACK_BLOCKED_STREAMS = 0x07 */
  TEST_ASSERT (SETTINGS_QPACK_BLOCKED_STREAMS == 0x07,
               "SETTINGS_QPACK_BLOCKED_STREAMS should be 0x07");

  printf ("PASS\n");
}

static void
test_settings_limits (void)
{
  printf ("  Settings limits match RFC 9204... ");

  /* RFC 9204 Section 5: max_table_capacity limit is 2^30 - 1 */
  TEST_ASSERT (QPACK_MAX_TABLE_CAPACITY_LIMIT == ((size_t)(1U << 30) - 1),
               "max_table_capacity limit should be 2^30 - 1");

  /* RFC 9204 Section 5: blocked_streams limit is 2^16 - 1 */
  TEST_ASSERT (QPACK_MAX_BLOCKED_STREAMS_LIMIT == ((size_t)(1U << 16) - 1),
               "blocked_streams limit should be 2^16 - 1");

  printf ("PASS\n");
}

/* ============================================================================
 * Settings Default Tests
 * ============================================================================
 */

static void
test_settings_defaults (void)
{
  SocketQPACK_Settings settings;
  SocketQPACK_ConfigResult result;

  printf ("  Default settings are (0, 0) per RFC... ");

  /* Initialize with non-zero to ensure defaults overwrite */
  settings.max_table_capacity = 9999;
  settings.blocked_streams = 9999;

  result = SocketQPACK_settings_defaults (&settings);
  TEST_ASSERT (result == QPACK_CONFIG_OK, "defaults should succeed");

  /* RFC 9204 Section 5: "The default value is zero." */
  TEST_ASSERT (settings.max_table_capacity == 0,
               "default max_table_capacity should be 0");
  TEST_ASSERT (settings.blocked_streams == 0,
               "default blocked_streams should be 0");

  printf ("PASS\n");
}

static void
test_settings_defaults_null (void)
{
  SocketQPACK_ConfigResult result;

  printf ("  Settings defaults handles NULL... ");

  result = SocketQPACK_settings_defaults (NULL);
  TEST_ASSERT (result == QPACK_CONFIG_ERROR_NULL_PARAM,
               "NULL should return error");

  printf ("PASS\n");
}

/* ============================================================================
 * Settings Validation Tests
 * ============================================================================
 */

static void
test_settings_validate_valid (void)
{
  SocketQPACK_Settings settings;
  SocketQPACK_ConfigResult result;

  printf ("  Validate accepts valid settings... ");

  /* Test with defaults (0, 0) */
  SocketQPACK_settings_defaults (&settings);
  result = SocketQPACK_settings_validate (&settings);
  TEST_ASSERT (result == QPACK_CONFIG_OK, "defaults should be valid");

  /* Test with typical values */
  settings.max_table_capacity = 4096;
  settings.blocked_streams = 100;
  result = SocketQPACK_settings_validate (&settings);
  TEST_ASSERT (result == QPACK_CONFIG_OK, "typical values should be valid");

  /* Test with maximum allowed values */
  settings.max_table_capacity = QPACK_MAX_TABLE_CAPACITY_LIMIT;
  settings.blocked_streams = QPACK_MAX_BLOCKED_STREAMS_LIMIT;
  result = SocketQPACK_settings_validate (&settings);
  TEST_ASSERT (result == QPACK_CONFIG_OK, "max values should be valid");

  printf ("PASS\n");
}

static void
test_settings_validate_invalid_capacity (void)
{
  SocketQPACK_Settings settings;
  SocketQPACK_ConfigResult result;

  printf ("  Validate rejects invalid capacity... ");

  SocketQPACK_settings_defaults (&settings);

  /* Exceed max capacity limit */
  settings.max_table_capacity = QPACK_MAX_TABLE_CAPACITY_LIMIT + 1;
  result = SocketQPACK_settings_validate (&settings);
  TEST_ASSERT (result == QPACK_CONFIG_ERROR_INVALID_VALUE,
               "exceeding capacity limit should fail");

  printf ("PASS\n");
}

static void
test_settings_validate_invalid_blocked (void)
{
  SocketQPACK_Settings settings;
  SocketQPACK_ConfigResult result;

  printf ("  Validate rejects invalid blocked_streams... ");

  SocketQPACK_settings_defaults (&settings);

  /* Exceed max blocked_streams limit */
  settings.blocked_streams = QPACK_MAX_BLOCKED_STREAMS_LIMIT + 1;
  result = SocketQPACK_settings_validate (&settings);
  TEST_ASSERT (result == QPACK_CONFIG_ERROR_INVALID_VALUE,
               "exceeding blocked_streams limit should fail");

  printf ("PASS\n");
}

static void
test_settings_validate_null (void)
{
  SocketQPACK_ConfigResult result;

  printf ("  Validate handles NULL... ");

  result = SocketQPACK_settings_validate (NULL);
  TEST_ASSERT (result == QPACK_CONFIG_ERROR_NULL_PARAM,
               "NULL should return error");

  printf ("PASS\n");
}

/* ============================================================================
 * Settings Query Tests
 * ============================================================================
 */

static void
test_settings_dynamic_table_check (void)
{
  SocketQPACK_Settings settings;
  int result;

  printf ("  Dynamic table check... ");

  /* Zero capacity disables dynamic table */
  SocketQPACK_settings_defaults (&settings);
  result = SocketQPACK_settings_has_dynamic_table (&settings);
  TEST_ASSERT (result == 0, "zero capacity should disable dynamic table");

  /* Non-zero capacity enables dynamic table */
  settings.max_table_capacity = 4096;
  result = SocketQPACK_settings_has_dynamic_table (&settings);
  TEST_ASSERT (result != 0, "non-zero capacity should enable dynamic table");

  /* NULL check */
  result = SocketQPACK_settings_has_dynamic_table (NULL);
  TEST_ASSERT (result == 0, "NULL should return false");

  printf ("PASS\n");
}

static void
test_settings_blocking_check (void)
{
  SocketQPACK_Settings settings;
  int result;

  printf ("  Blocking allowed check... ");

  /* Zero blocked_streams disallows blocking */
  SocketQPACK_settings_defaults (&settings);
  result = SocketQPACK_settings_allows_blocking (&settings);
  TEST_ASSERT (result == 0, "zero blocked_streams should disallow blocking");

  /* Non-zero blocked_streams allows blocking */
  settings.blocked_streams = 100;
  result = SocketQPACK_settings_allows_blocking (&settings);
  TEST_ASSERT (result != 0, "non-zero blocked_streams should allow blocking");

  /* NULL check */
  result = SocketQPACK_settings_allows_blocking (NULL);
  TEST_ASSERT (result == 0, "NULL should return false");

  printf ("PASS\n");
}

/* ============================================================================
 * Configuration Tests
 * ============================================================================
 */

static void
test_config_new (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;

  printf ("  Config new creates valid config... ");

  arena = Arena_new ();
  TEST_ASSERT (arena != NULL, "arena should be created");

  config = SocketQPACK_config_new (arena);
  TEST_ASSERT (config != NULL, "config should be created");

  /* Should not be ready (no peer settings yet) */
  TEST_ASSERT (SocketQPACK_config_is_ready (config) == 0,
               "new config should not be ready");

  /* Should not be using 0-RTT */
  TEST_ASSERT (SocketQPACK_config_is_0rtt (config) == 0,
               "new config should not be 0-RTT");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_config_set_local (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;
  SocketQPACK_Settings settings;
  SocketQPACK_ConfigResult result;
  const SocketQPACK_Settings *decoder_settings;

  printf ("  Config set local settings... ");

  arena = Arena_new ();
  config = SocketQPACK_config_new (arena);

  settings.max_table_capacity = 8192;
  settings.blocked_streams = 50;

  result = SocketQPACK_config_set_local (config, &settings);
  TEST_ASSERT (result == QPACK_CONFIG_OK, "set local should succeed");

  /* Decoder uses local settings */
  decoder_settings = SocketQPACK_config_decoder_settings (config);
  TEST_ASSERT (decoder_settings != NULL, "decoder settings should exist");
  TEST_ASSERT (decoder_settings->max_table_capacity == 8192,
               "capacity should match");
  TEST_ASSERT (decoder_settings->blocked_streams == 50,
               "blocked_streams should match");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_config_apply_peer (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;
  SocketQPACK_Settings settings;
  SocketQPACK_ConfigResult result;
  const SocketQPACK_Settings *encoder_settings;

  printf ("  Config apply peer settings... ");

  arena = Arena_new ();
  config = SocketQPACK_config_new (arena);

  settings.max_table_capacity = 16384;
  settings.blocked_streams = 200;

  result = SocketQPACK_config_apply_peer (config, &settings);
  TEST_ASSERT (result == QPACK_CONFIG_OK, "apply peer should succeed");

  /* Config should now be ready */
  TEST_ASSERT (SocketQPACK_config_is_ready (config) != 0,
               "config should be ready after peer settings");

  /* Encoder uses peer settings */
  encoder_settings = SocketQPACK_config_encoder_settings (config);
  TEST_ASSERT (encoder_settings != NULL, "encoder settings should exist");
  TEST_ASSERT (encoder_settings->max_table_capacity == 16384,
               "capacity should match");
  TEST_ASSERT (encoder_settings->blocked_streams == 200,
               "blocked_streams should match");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_config_apply_peer_invalid (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;
  SocketQPACK_Settings settings;
  SocketQPACK_ConfigResult result;

  printf ("  Config rejects invalid peer settings... ");

  arena = Arena_new ();
  config = SocketQPACK_config_new (arena);

  /* Invalid capacity */
  settings.max_table_capacity = QPACK_MAX_TABLE_CAPACITY_LIMIT + 1;
  settings.blocked_streams = 0;

  result = SocketQPACK_config_apply_peer (config, &settings);
  TEST_ASSERT (result == QPACK_CONFIG_ERROR_INVALID_VALUE,
               "invalid peer settings should fail");

  /* Config should not be ready */
  TEST_ASSERT (SocketQPACK_config_is_ready (config) == 0,
               "config should not be ready after failed apply");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_config_encoder_settings_not_ready (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;
  const SocketQPACK_Settings *encoder_settings;

  printf ("  Encoder settings NULL when peer not received... ");

  arena = Arena_new ();
  config = SocketQPACK_config_new (arena);

  /* No peer settings applied */
  encoder_settings = SocketQPACK_config_encoder_settings (config);
  TEST_ASSERT (encoder_settings == NULL,
               "encoder settings should be NULL before peer received");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * 0-RTT Tests
 * ============================================================================
 */

static void
test_config_0rtt_set (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;
  SocketQPACK_Settings previous;
  SocketQPACK_ConfigResult result;
  const SocketQPACK_Settings *encoder_settings;

  printf ("  0-RTT settings set... ");

  arena = Arena_new ();
  config = SocketQPACK_config_new (arena);

  previous.max_table_capacity = 4096;
  previous.blocked_streams = 100;

  result = SocketQPACK_config_set_0rtt (config, &previous, arena);
  TEST_ASSERT (result == QPACK_CONFIG_OK, "set 0-RTT should succeed");

  /* Should be using 0-RTT */
  TEST_ASSERT (SocketQPACK_config_is_0rtt (config) != 0,
               "should be using 0-RTT");

  /* Encoder should use 0-RTT settings */
  encoder_settings = SocketQPACK_config_encoder_settings (config);
  TEST_ASSERT (encoder_settings != NULL, "0-RTT encoder settings should exist");
  TEST_ASSERT (encoder_settings->max_table_capacity == 4096,
               "capacity should match 0-RTT");
  TEST_ASSERT (encoder_settings->blocked_streams == 100,
               "blocked_streams should match 0-RTT");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_config_0rtt_complete (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;
  SocketQPACK_Settings previous, peer;
  SocketQPACK_ConfigResult result;
  const SocketQPACK_Settings *encoder_settings;

  printf ("  0-RTT completion switches to negotiated... ");

  arena = Arena_new ();
  config = SocketQPACK_config_new (arena);

  /* Set 0-RTT settings */
  previous.max_table_capacity = 4096;
  previous.blocked_streams = 100;
  SocketQPACK_config_set_0rtt (config, &previous, arena);

  /* Apply new peer settings */
  peer.max_table_capacity = 8192;
  peer.blocked_streams = 200;
  SocketQPACK_config_apply_peer (config, &peer);

  /* Complete 0-RTT */
  result = SocketQPACK_config_complete_0rtt (config);
  TEST_ASSERT (result == QPACK_CONFIG_OK, "complete 0-RTT should succeed");

  /* Should no longer be using 0-RTT */
  TEST_ASSERT (SocketQPACK_config_is_0rtt (config) == 0,
               "should not be using 0-RTT after complete");

  /* Encoder should now use negotiated settings */
  encoder_settings = SocketQPACK_config_encoder_settings (config);
  TEST_ASSERT (encoder_settings != NULL, "encoder settings should exist");
  TEST_ASSERT (encoder_settings->max_table_capacity == 8192,
               "capacity should match negotiated");
  TEST_ASSERT (encoder_settings->blocked_streams == 200,
               "blocked_streams should match negotiated");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_config_0rtt_complete_not_ready (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;
  SocketQPACK_Settings previous;
  SocketQPACK_ConfigResult result;

  printf ("  0-RTT complete fails if peer not received... ");

  arena = Arena_new ();
  config = SocketQPACK_config_new (arena);

  /* Set 0-RTT settings but don't apply peer settings */
  previous.max_table_capacity = 4096;
  previous.blocked_streams = 100;
  SocketQPACK_config_set_0rtt (config, &previous, arena);

  /* Complete 0-RTT should fail */
  result = SocketQPACK_config_complete_0rtt (config);
  TEST_ASSERT (result == QPACK_CONFIG_ERROR_NOT_READY,
               "complete should fail without peer settings");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

static void
test_config_null_handling (void)
{
  SocketQPACK_Settings settings;

  printf ("  NULL handling... ");

  /* Set local with NULL config */
  TEST_ASSERT (SocketQPACK_config_set_local (NULL, &settings)
                   == QPACK_CONFIG_ERROR_NULL_PARAM,
               "set_local NULL config should fail");

  /* Apply peer with NULL config */
  TEST_ASSERT (SocketQPACK_config_apply_peer (NULL, &settings)
                   == QPACK_CONFIG_ERROR_NULL_PARAM,
               "apply_peer NULL config should fail");

  /* Set 0-RTT with NULL */
  TEST_ASSERT (
      SocketQPACK_config_set_0rtt (NULL, &settings, NULL)
          == QPACK_CONFIG_ERROR_NULL_PARAM,
      "set_0rtt NULL config should fail");

  /* Complete 0-RTT with NULL */
  TEST_ASSERT (SocketQPACK_config_complete_0rtt (NULL)
                   == QPACK_CONFIG_ERROR_NULL_PARAM,
               "complete_0rtt NULL should fail");

  /* Query functions with NULL */
  TEST_ASSERT (SocketQPACK_config_encoder_settings (NULL) == NULL,
               "encoder_settings NULL should return NULL");
  TEST_ASSERT (SocketQPACK_config_decoder_settings (NULL) == NULL,
               "decoder_settings NULL should return NULL");
  TEST_ASSERT (SocketQPACK_config_is_ready (NULL) == 0,
               "is_ready NULL should return 0");
  TEST_ASSERT (SocketQPACK_config_is_0rtt (NULL) == 0,
               "is_0rtt NULL should return 0");

  printf ("PASS\n");
}

static void
test_config_zero_capacity (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;
  SocketQPACK_Settings settings;
  const SocketQPACK_Settings *encoder_settings;

  printf ("  Zero capacity disables dynamic table... ");

  arena = Arena_new ();
  config = SocketQPACK_config_new (arena);

  settings.max_table_capacity = 0;
  settings.blocked_streams = 100;

  SocketQPACK_config_apply_peer (config, &settings);

  encoder_settings = SocketQPACK_config_encoder_settings (config);
  TEST_ASSERT (encoder_settings != NULL, "settings should exist");
  TEST_ASSERT (SocketQPACK_settings_has_dynamic_table (encoder_settings) == 0,
               "dynamic table should be disabled");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_config_zero_blocked (void)
{
  Arena_T arena;
  SocketQPACK_Config_T config;
  SocketQPACK_Settings settings;
  const SocketQPACK_Settings *encoder_settings;

  printf ("  Zero blocked_streams disallows blocking... ");

  arena = Arena_new ();
  config = SocketQPACK_config_new (arena);

  settings.max_table_capacity = 4096;
  settings.blocked_streams = 0;

  SocketQPACK_config_apply_peer (config, &settings);

  encoder_settings = SocketQPACK_config_encoder_settings (config);
  TEST_ASSERT (encoder_settings != NULL, "settings should exist");
  TEST_ASSERT (SocketQPACK_settings_allows_blocking (encoder_settings) == 0,
               "blocking should be disallowed");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_result_string (void)
{
  printf ("  Result string lookup... ");

  TEST_ASSERT (
      strcmp (SocketQPACK_config_result_string (QPACK_CONFIG_OK), "OK") == 0,
      "OK string");
  TEST_ASSERT (
      SocketQPACK_config_result_string (QPACK_CONFIG_ERROR_INVALID_VALUE)
          != NULL,
      "invalid value string");
  TEST_ASSERT (
      SocketQPACK_config_result_string (QPACK_CONFIG_ERROR_NULL_PARAM) != NULL,
      "null param string");
  TEST_ASSERT (SocketQPACK_config_result_string ((SocketQPACK_ConfigResult)999)
                   != NULL,
               "unknown error string");

  printf ("PASS\n");
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("QPACK Configuration Unit Tests (RFC 9204 Section 5)\n");
  printf ("====================================================\n\n");

  printf ("Settings Identifier Tests:\n");
  test_settings_identifiers ();
  test_settings_limits ();

  printf ("\nSettings Default Tests:\n");
  test_settings_defaults ();
  test_settings_defaults_null ();

  printf ("\nSettings Validation Tests:\n");
  test_settings_validate_valid ();
  test_settings_validate_invalid_capacity ();
  test_settings_validate_invalid_blocked ();
  test_settings_validate_null ();

  printf ("\nSettings Query Tests:\n");
  test_settings_dynamic_table_check ();
  test_settings_blocking_check ();

  printf ("\nConfiguration Tests:\n");
  test_config_new ();
  test_config_set_local ();
  test_config_apply_peer ();
  test_config_apply_peer_invalid ();
  test_config_encoder_settings_not_ready ();

  printf ("\n0-RTT Tests:\n");
  test_config_0rtt_set ();
  test_config_0rtt_complete ();
  test_config_0rtt_complete_not_ready ();

  printf ("\nEdge Case Tests:\n");
  test_config_null_handling ();
  test_config_zero_capacity ();
  test_config_zero_blocked ();
  test_result_string ();

  printf ("\n====================================================\n");
  printf ("All QPACK Configuration tests passed!\n");

  return 0;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_pool_health.c - Comprehensive SocketPoolHealth unit tests
 * Tests circuit breaker, health checks, and resilience patterns.
 */

/* cppcheck-suppress-file constVariablePointer ; test allocation success */
/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"
#include "pool/SocketPool.h"
#include "pool/SocketPoolHealth.h"
#include "socket/Socket.h"
#include "test/Test.h"

/* Suppress longjmp clobbering warnings for test variables used with TRY/EXCEPT
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* ==================== Helper Functions ==================== */

/**
 * @brief Create a basic pool for testing health checks.
 */
static SocketPool_T
create_test_pool (Arena_T arena)
{
  return SocketPool_new (arena, 100, 1024);
}

/**
 * @brief Sleep for milliseconds (helper for timeout tests).
 */
static void
sleep_ms (int ms)
{
  struct timespec ts;
  ts = socket_util_ms_to_timespec ((unsigned long)ms);
  nanosleep (&ts, NULL);
}

/* ==================== Default Config Tests ==================== */

TEST (health_config_defaults_initializes_properly)
{
  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  ASSERT (config.failure_threshold > 0);
  ASSERT (config.reset_timeout_ms > 0);
  ASSERT (config.half_open_max_probes > 0);
  ASSERT (config.probe_interval_ms > 0);
  ASSERT (config.probe_timeout_ms > 0);
  ASSERT (config.probes_per_cycle > 0);
}

TEST (health_config_defaults_has_reasonable_values)
{
  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  /* Check for reasonable production defaults */
  ASSERT (config.failure_threshold >= 3);
  ASSERT (config.failure_threshold <= 10);
  ASSERT (config.reset_timeout_ms >= 10000); /* At least 10 seconds */
  ASSERT (config.probe_interval_ms >= 1000); /* At least 1 second */
  ASSERT (config.half_open_max_probes >= 1);
}

/* ==================== Enable/Disable Tests ==================== */

TEST (health_enable_creates_health_subsystem)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  TRY
  {
    int result = SocketPool_enable_health_checks (pool, &config);
    ASSERT_EQ (0, result);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0); /* Should not fail */
  }
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (health_enable_multiple_times_succeeds)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  TRY
  {
    /* Enable first time */
    int result1 = SocketPool_enable_health_checks (pool, &config);
    ASSERT_EQ (0, result1);

    /* Enable again (should update config, not fail) */
    int result2 = SocketPool_enable_health_checks (pool, &config);
    ASSERT_EQ (0, result2);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (health_disable_stops_background_thread)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  TRY
  {
    int result = SocketPool_enable_health_checks (pool, &config);
    ASSERT_EQ (0, result);

    /* Give thread time to start */
    sleep_ms (100);

    /* Disable should cleanly shut down */
    SocketPool_disable_health_checks (pool);

    /* Should be safe to disable again (no-op) */
    SocketPool_disable_health_checks (pool);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Circuit State Tests ==================== */

TEST (circuit_state_defaults_to_closed)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    /* New circuit should be CLOSED */
    SocketPoolCircuit_State state
        = SocketPool_circuit_state (pool, "example.com", 80);
    ASSERT_EQ (POOL_CIRCUIT_CLOSED, state);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (circuit_allows_when_closed)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    /* CLOSED circuit should allow connections */
    int allowed = SocketPool_circuit_allows (pool, "example.com", 80);
    ASSERT (allowed);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Failure Threshold Tests ==================== */

TEST (circuit_opens_after_threshold_failures)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 3; /* Low threshold for testing */

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host = "test.example.com";
    int port = 443;

    /* Report failures up to threshold */
    for (int i = 0; i < config.failure_threshold; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port);
      }

    /* Circuit should now be OPEN */
    SocketPoolCircuit_State state = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_OPEN, state);

    /* Should block new connections */
    int allowed = SocketPool_circuit_allows (pool, host, port);
    ASSERT_EQ (0, allowed);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (circuit_stays_closed_below_threshold)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 5;

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host = "test.example.com";
    int port = 443;

    /* Report failures below threshold */
    for (int i = 0; i < config.failure_threshold - 1; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port);
      }

    /* Circuit should still be CLOSED */
    SocketPoolCircuit_State state = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_CLOSED, state);

    /* Should still allow connections */
    int allowed = SocketPool_circuit_allows (pool, host, port);
    ASSERT (allowed);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Success Reporting Tests ==================== */

TEST (success_resets_failure_counter)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 5;

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host = "test.example.com";
    int port = 443;

    /* Report some failures */
    for (int i = 0; i < 3; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port);
      }

    /* Report success (should reset counter) */
    SocketPool_circuit_report_success (pool, host, port);

    /* Now report more failures (starting from 0 again) */
    for (int i = 0; i < config.failure_threshold - 1; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port);
      }

    /* Circuit should still be CLOSED (counter was reset) */
    SocketPoolCircuit_State state = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_CLOSED, state);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Half-Open State Tests ==================== */

TEST (circuit_transitions_to_half_open_after_timeout)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 3;
  config.reset_timeout_ms = 500; /* Short timeout for testing */

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host = "test.example.com";
    int port = 443;

    /* Open the circuit */
    for (int i = 0; i < config.failure_threshold; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port);
      }

    /* Verify it's OPEN */
    SocketPoolCircuit_State state1
        = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_OPEN, state1);

    /* Wait for reset timeout */
    sleep_ms (config.reset_timeout_ms + 100);

    /* First circuit_allows() call should transition to HALF_OPEN */
    int allowed = SocketPool_circuit_allows (pool, host, port);
    ASSERT (allowed); /* Should allow first probe */

    SocketPoolCircuit_State state2
        = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_HALF_OPEN, state2);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (half_open_limits_concurrent_probes)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 2;
  config.reset_timeout_ms = 500;
  config.half_open_max_probes = 2; /* Allow only 2 probes */

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host = "test.example.com";
    int port = 443;

    /* Open the circuit */
    for (int i = 0; i < config.failure_threshold; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port);
      }

    /* Wait for reset timeout */
    sleep_ms (config.reset_timeout_ms + 100);

    /* First two probes should be allowed */
    int allowed1 = SocketPool_circuit_allows (pool, host, port);
    ASSERT (allowed1);

    int allowed2 = SocketPool_circuit_allows (pool, host, port);
    ASSERT (allowed2);

    /* Third probe should be blocked (max reached) */
    int allowed3 = SocketPool_circuit_allows (pool, host, port);
    ASSERT_EQ (0, allowed3);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (half_open_success_closes_circuit)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 2;
  config.reset_timeout_ms = 500;

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host = "test.example.com";
    int port = 443;

    /* Open the circuit */
    for (int i = 0; i < config.failure_threshold; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port);
      }

    /* Wait for reset timeout */
    sleep_ms (config.reset_timeout_ms + 100);

    /* Transition to HALF_OPEN */
    SocketPool_circuit_allows (pool, host, port);

    /* Report success - should close circuit */
    SocketPool_circuit_report_success (pool, host, port);

    SocketPoolCircuit_State state = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_CLOSED, state);

    /* Should now allow unlimited connections */
    int allowed = SocketPool_circuit_allows (pool, host, port);
    ASSERT (allowed);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (half_open_failure_reopens_circuit)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 2;
  config.reset_timeout_ms = 500;

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host = "test.example.com";
    int port = 443;

    /* Open the circuit */
    for (int i = 0; i < config.failure_threshold; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port);
      }

    /* Wait for reset timeout */
    sleep_ms (config.reset_timeout_ms + 100);

    /* Transition to HALF_OPEN */
    SocketPool_circuit_allows (pool, host, port);

    SocketPoolCircuit_State state1
        = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_HALF_OPEN, state1);

    /* Report failure in half-open - should go back to OPEN */
    SocketPool_circuit_report_failure (pool, host, port);

    SocketPoolCircuit_State state2
        = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_OPEN, state2);

    /* Should block connections */
    int allowed = SocketPool_circuit_allows (pool, host, port);
    ASSERT_EQ (0, allowed);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Manual Reset Tests ==================== */

TEST (circuit_reset_closes_open_circuit)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 2;

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host = "test.example.com";
    int port = 443;

    /* Open the circuit */
    for (int i = 0; i < config.failure_threshold; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port);
      }

    SocketPoolCircuit_State state1
        = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_OPEN, state1);

    /* Manually reset */
    int result = SocketPool_circuit_reset (pool, host, port);
    ASSERT_EQ (0, result);

    /* Should now be CLOSED */
    SocketPoolCircuit_State state2
        = SocketPool_circuit_state (pool, host, port);
    ASSERT_EQ (POOL_CIRCUIT_CLOSED, state2);

    /* Should allow connections */
    int allowed = SocketPool_circuit_allows (pool, host, port);
    ASSERT (allowed);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (circuit_reset_unknown_host_returns_error)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    /* Try to reset circuit that was never created */
    int result = SocketPool_circuit_reset (pool, "nonexistent.com", 999);
    ASSERT_EQ (-1, result);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Multiple Hosts Tests ==================== */

TEST (circuit_tracks_multiple_hosts_independently)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 2;

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host1 = "service1.example.com";
    const char *host2 = "service2.example.com";
    int port = 443;

    /* Open circuit for host1 */
    for (int i = 0; i < config.failure_threshold; i++)
      {
        SocketPool_circuit_report_failure (pool, host1, port);
      }

    /* host1 should be OPEN */
    SocketPoolCircuit_State state1
        = SocketPool_circuit_state (pool, host1, port);
    ASSERT_EQ (POOL_CIRCUIT_OPEN, state1);

    /* host2 should still be CLOSED */
    SocketPoolCircuit_State state2
        = SocketPool_circuit_state (pool, host2, port);
    ASSERT_EQ (POOL_CIRCUIT_CLOSED, state2);

    /* host1 should block, host2 should allow */
    int allowed1 = SocketPool_circuit_allows (pool, host1, port);
    int allowed2 = SocketPool_circuit_allows (pool, host2, port);

    ASSERT_EQ (0, allowed1);
    ASSERT (allowed2);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (circuit_tracks_same_host_different_ports)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 2;

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    const char *host = "example.com";
    int port1 = 80;
    int port2 = 443;

    /* Open circuit for port 80 */
    for (int i = 0; i < config.failure_threshold; i++)
      {
        SocketPool_circuit_report_failure (pool, host, port1);
      }

    /* port1 should be OPEN */
    SocketPoolCircuit_State state1
        = SocketPool_circuit_state (pool, host, port1);
    ASSERT_EQ (POOL_CIRCUIT_OPEN, state1);

    /* port2 should still be CLOSED */
    SocketPoolCircuit_State state2
        = SocketPool_circuit_state (pool, host, port2);
    ASSERT_EQ (POOL_CIRCUIT_CLOSED, state2);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Health Statistics Tests ==================== */

TEST (health_stats_track_circuit_opens)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);
  config.failure_threshold = 2;

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    uint64_t circuits_opened_before = 0;
    SocketPool_health_stats (pool, NULL, NULL, NULL, &circuits_opened_before);

    /* Open a circuit */
    for (int i = 0; i < config.failure_threshold; i++)
      {
        SocketPool_circuit_report_failure (pool, "test.com", 443);
      }

    uint64_t circuits_opened_after = 0;
    SocketPool_health_stats (pool, NULL, NULL, NULL, &circuits_opened_after);

    /* Should have incremented */
    ASSERT (circuits_opened_after > circuits_opened_before);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (health_stats_accepts_null_parameters)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    /* Should not crash with NULL parameters */
    SocketPool_health_stats (pool, NULL, NULL, NULL, NULL);

    uint64_t probes_sent = 0;
    SocketPool_health_stats (pool, &probes_sent, NULL, NULL, NULL);

    /* Just verify it doesn't crash */
    ASSERT (1);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Edge Cases ==================== */

TEST (health_checks_without_enable_are_noop)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  /* Don't enable health checks */

  /* These should be safe to call and return defaults */
  int allowed = SocketPool_circuit_allows (pool, "test.com", 443);
  ASSERT (allowed); /* Should allow when health checks disabled */

  SocketPoolCircuit_State state
      = SocketPool_circuit_state (pool, "test.com", 443);
  ASSERT_EQ (POOL_CIRCUIT_CLOSED, state);

  /* Should be safe to report (just ignored) */
  SocketPool_circuit_report_failure (pool, "test.com", 443);
  SocketPool_circuit_report_success (pool, "test.com", 443);

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (circuit_handles_null_host_gracefully)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    /* These should handle NULL host gracefully (return defaults) */
    int allowed = SocketPool_circuit_allows (pool, NULL, 443);
    ASSERT (allowed); /* Should allow to avoid blocking everything */

    SocketPoolCircuit_State state = SocketPool_circuit_state (pool, NULL, 443);
    ASSERT_EQ (POOL_CIRCUIT_CLOSED, state);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Thread Safety Test ==================== */

/* Helper for concurrent circuit operations */
static void *
circuit_stress_thread (void *arg)
{
  SocketPool_T pool = (SocketPool_T)arg;

  for (int i = 0; i < 100; i++)
    {
      /* Mix of operations */
      SocketPool_circuit_allows (pool, "concurrent.test", 443);
      SocketPool_circuit_report_failure (pool, "concurrent.test", 443);
      SocketPool_circuit_state (pool, "concurrent.test", 443);
      SocketPool_circuit_report_success (pool, "concurrent.test", 443);
    }

  return NULL;
}

TEST (circuit_operations_are_thread_safe)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketPool_T pool = create_test_pool (arena);
  ASSERT_NOT_NULL (pool);

  SocketPoolHealth_Config config;
  SocketPoolHealth_config_defaults (&config);

  TRY
  {
    SocketPool_enable_health_checks (pool, &config);

    /* Launch multiple threads doing circuit operations */
    const int num_threads = 4;
    pthread_t threads[num_threads];

    for (int i = 0; i < num_threads; i++)
      {
        int rc
            = pthread_create (&threads[i], NULL, circuit_stress_thread, pool);
        ASSERT_EQ (0, rc);
      }

    /* Wait for all threads */
    for (int i = 0; i < num_threads; i++)
      {
        pthread_join (threads[i], NULL);
      }

    /* If we got here without crashes, thread safety works */
    ASSERT (1);
  }
  EXCEPT (SocketPool_Failed)
  {
    ASSERT (0);
  }
  END_TRY;

  SocketPool_disable_health_checks (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Main Test Entry Point ==================== */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

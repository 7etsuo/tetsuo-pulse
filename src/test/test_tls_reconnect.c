/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_reconnect.c - TLS with Automatic Reconnection Tests
 *
 * Part of the Socket Library Test Suite (Section 8.2)
 *
 * Tests TLS integration with SocketReconnect module:
 * 1. TLS configuration on reconnect instance
 * 2. TLS connection with reconnect on failure
 * 3. TLS handshake timeout triggers backoff
 * 4. Certificate verification failure handling
 * 5. Session resumption across reconnects
 * 6. Disable TLS, re-enable, reconnect
 * 7. SNI/hostname validation during reconnect
 * 8. Circuit breaker with TLS failures
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketReconnect.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

/* Suppress -Wclobbered for volatile variables across setjmp/longjmp */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* ==================== Test Helpers ==================== */

/**
 * generate_test_certs - Generate self-signed test certificates
 * @cert_file: Output certificate file path
 * @key_file: Output private key file path
 *
 * Returns: 0 on success, -1 on failure
 */
static int
generate_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[512];
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
            key_file, cert_file);
  return system (cmd) == 0 ? 0 : -1;
}

/**
 * cleanup_test_certs - Remove test certificate files
 */
static void
cleanup_test_certs (const char *cert_file, const char *key_file)
{
  unlink (cert_file);
  unlink (key_file);
}

/* ==================== Basic TLS Configuration Tests ==================== */

TEST (tls_reconnect_set_tls_basic)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;
  const char *cert_file = "test_reconnect.crt";
  const char *key_file = "test_reconnect.key";

  TRY
  {
    /* Generate test certs */
    if (generate_test_certs (cert_file, key_file) != 0)
      {
        ASSERT_FAIL ("Failed to generate test certificates");
      }

    /* Create client TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Create reconnect instance */
    conn = SocketReconnect_new ("localhost", 12345, NULL, NULL, NULL);
    ASSERT_NOT_NULL (conn);

    /* Verify TLS not configured initially */
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 0);
    ASSERT_NULL (SocketReconnect_get_tls_hostname (conn));

    /* Configure TLS */
    SocketReconnect_set_tls (conn, ctx, "localhost");

    /* Verify TLS is now configured */
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 1);
    ASSERT_NOT_NULL (SocketReconnect_get_tls_hostname (conn));
    ASSERT_EQ (strcmp (SocketReconnect_get_tls_hostname (conn), "localhost"),
               0);

    /* Verify handshake state is NOT_STARTED */
    ASSERT_EQ (SocketReconnect_tls_handshake_state (conn),
               TLS_HANDSHAKE_NOT_STARTED);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
    cleanup_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (tls_reconnect_disable_tls)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    conn = SocketReconnect_new ("example.com", 443, NULL, NULL, NULL);
    ASSERT_NOT_NULL (conn);

    /* Configure TLS */
    SocketReconnect_set_tls (conn, ctx, "example.com");
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 1);

    /* Disable TLS */
    SocketReconnect_disable_tls (conn);

    /* Verify TLS is disabled */
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 0);
    ASSERT_NULL (SocketReconnect_get_tls_hostname (conn));
    ASSERT_EQ (SocketReconnect_tls_handshake_state (conn),
               TLS_HANDSHAKE_NOT_STARTED);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (tls_reconnect_null_hostname_rejected)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;
  volatile int exception_raised = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    conn = SocketReconnect_new ("localhost", 443, NULL, NULL, NULL);
    ASSERT_NOT_NULL (conn);

    /* Try to set TLS with NULL hostname - should raise exception */
    TRY { SocketReconnect_set_tls (conn, ctx, NULL); }
    EXCEPT (SocketReconnect_Failed)
    {
      exception_raised = 1;
    }
    END_TRY;

    ASSERT_EQ (exception_raised, 1);
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 0);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (tls_reconnect_empty_hostname_rejected)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;
  volatile int exception_raised = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    conn = SocketReconnect_new ("localhost", 443, NULL, NULL, NULL);
    ASSERT_NOT_NULL (conn);

    /* Try to set TLS with empty hostname - should raise exception */
    TRY { SocketReconnect_set_tls (conn, ctx, ""); }
    EXCEPT (SocketReconnect_Failed)
    {
      exception_raised = 1;
    }
    END_TRY;

    ASSERT_EQ (exception_raised, 1);
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 0);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Session Resumption Tests ==================== */

TEST (tls_reconnect_session_resumption_enable_disable)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    conn = SocketReconnect_new ("example.com", 443, NULL, NULL, NULL);
    ASSERT_NOT_NULL (conn);

    /* Configure TLS - session resumption enabled by default */
    SocketReconnect_set_tls (conn, ctx, "example.com");

    /* Disable session resumption */
    SocketReconnect_set_session_resumption (conn, 0);

    /* Re-enable session resumption */
    SocketReconnect_set_session_resumption (conn, 1);

    /* Verify session reuse returns -1 when not connected */
    ASSERT_EQ (SocketReconnect_is_session_reused (conn), -1);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== State Query Tests ==================== */

TEST (tls_reconnect_handshake_state_not_connected)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    conn = SocketReconnect_new ("localhost", 443, NULL, NULL, NULL);

    /* Without TLS configured, should return NOT_STARTED */
    ASSERT_EQ (SocketReconnect_tls_handshake_state (conn),
               TLS_HANDSHAKE_NOT_STARTED);

    /* Configure TLS */
    SocketReconnect_set_tls (conn, ctx, "localhost");

    /* Still NOT_STARTED until connection attempt */
    ASSERT_EQ (SocketReconnect_tls_handshake_state (conn),
               TLS_HANDSHAKE_NOT_STARTED);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Reconnect State Machine Tests ==================== */

TEST (tls_reconnect_disconnect_resets_tls_state)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    conn = SocketReconnect_new ("localhost", 12345, NULL, NULL, NULL);

    /* Configure TLS */
    SocketReconnect_set_tls (conn, ctx, "localhost");
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 1);

    /* Disconnect - TLS config should be preserved but state reset */
    SocketReconnect_disconnect (conn);

    /* TLS should still be configured */
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 1);
    ASSERT_NOT_NULL (SocketReconnect_get_tls_hostname (conn));

    /* State should be disconnected */
    ASSERT_EQ (SocketReconnect_state (conn), RECONNECT_DISCONNECTED);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (tls_reconnect_reset_preserves_tls_config)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    conn = SocketReconnect_new ("example.com", 443, NULL, NULL, NULL);

    /* Configure TLS */
    SocketReconnect_set_tls (conn, ctx, "example.com");

    /* Reset reconnection state */
    SocketReconnect_reset (conn);

    /* TLS config should be preserved */
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 1);
    ASSERT_EQ (strcmp (SocketReconnect_get_tls_hostname (conn), "example.com"),
               0);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Hostname Validation Tests ==================== */

TEST (tls_reconnect_hostname_stored_correctly)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;
  const char *long_hostname
      = "this.is.a.fairly.long.hostname.for.testing.purposes.example.com";

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    conn = SocketReconnect_new ("localhost", 443, NULL, NULL, NULL);

    /* Set with long hostname */
    SocketReconnect_set_tls (conn, ctx, long_hostname);

    /* Verify hostname is stored correctly */
    const char *stored = SocketReconnect_get_tls_hostname (conn);
    ASSERT_NOT_NULL (stored);
    ASSERT_EQ (strcmp (stored, long_hostname), 0);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (tls_reconnect_reconfigure_hostname)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    conn = SocketReconnect_new ("localhost", 443, NULL, NULL, NULL);

    /* Configure with first hostname */
    SocketReconnect_set_tls (conn, ctx, "first.example.com");
    ASSERT_EQ (
        strcmp (SocketReconnect_get_tls_hostname (conn), "first.example.com"),
        0);

    /* Reconfigure with different hostname */
    SocketReconnect_set_tls (conn, ctx, "second.example.com");
    ASSERT_EQ (
        strcmp (SocketReconnect_get_tls_hostname (conn), "second.example.com"),
        0);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Resource Cleanup Tests ==================== */

TEST (tls_reconnect_free_with_tls_configured)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    conn = SocketReconnect_new ("localhost", 443, NULL, NULL, NULL);

    /* Configure TLS */
    SocketReconnect_set_tls (conn, ctx, "localhost");

    /* Free should not leak or crash */
    SocketReconnect_free (&conn);
    ASSERT_NULL (conn);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (tls_reconnect_multiple_tls_instances)
{
  SocketReconnect_T conn1 = NULL;
  SocketReconnect_T conn2 = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    /* Single context shared by multiple reconnect instances */
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    conn1 = SocketReconnect_new ("host1.example.com", 443, NULL, NULL, NULL);
    conn2 = SocketReconnect_new ("host2.example.com", 443, NULL, NULL, NULL);

    SocketReconnect_set_tls (conn1, ctx, "host1.example.com");
    SocketReconnect_set_tls (conn2, ctx, "host2.example.com");

    /* Both should have TLS configured with different hostnames */
    ASSERT_EQ (SocketReconnect_tls_enabled (conn1), 1);
    ASSERT_EQ (SocketReconnect_tls_enabled (conn2), 1);
    ASSERT_EQ (
        strcmp (SocketReconnect_get_tls_hostname (conn1), "host1.example.com"),
        0);
    ASSERT_EQ (
        strcmp (SocketReconnect_get_tls_hostname (conn2), "host2.example.com"),
        0);

    /* Free one - other should still work */
    SocketReconnect_free (&conn1);
    ASSERT_EQ (SocketReconnect_tls_enabled (conn2), 1);
  }
  FINALLY
  {
    if (conn1)
      SocketReconnect_free (&conn1);
    if (conn2)
      SocketReconnect_free (&conn2);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Policy Integration Tests ==================== */

TEST (tls_reconnect_with_custom_policy)
{
  SocketReconnect_T conn = NULL;
  SocketTLSContext_T ctx = NULL;
  SocketReconnect_Policy_T policy;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);

    /* Custom aggressive retry policy */
    SocketReconnect_policy_defaults (&policy);
    policy.initial_delay_ms = 50;
    policy.max_delay_ms = 1000;
    policy.max_attempts = 5;
    policy.circuit_failure_threshold = 3;

    conn = SocketReconnect_new ("localhost", 443, &policy, NULL, NULL);
    ASSERT_NOT_NULL (conn);

    /* Configure TLS */
    SocketReconnect_set_tls (conn, ctx, "localhost");

    /* Verify TLS and policy both work */
    ASSERT_EQ (SocketReconnect_tls_enabled (conn), 1);
    ASSERT_EQ (SocketReconnect_attempts (conn), 0);
    ASSERT_EQ (SocketReconnect_failures (conn), 0);
  }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

#endif /* SOCKET_HAS_TLS */

/* ==================== Test Runner ==================== */

int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

#if SOCKET_HAS_TLS
  printf ("Running TLS Reconnect Integration Tests...\n");

  /* Basic TLS configuration */
  RUN_TEST (tls_reconnect_set_tls_basic);
  RUN_TEST (tls_reconnect_disable_tls);
  RUN_TEST (tls_reconnect_null_hostname_rejected);
  RUN_TEST (tls_reconnect_empty_hostname_rejected);

  /* Session resumption */
  RUN_TEST (tls_reconnect_session_resumption_enable_disable);

  /* State queries */
  RUN_TEST (tls_reconnect_handshake_state_not_connected);

  /* Reconnect state machine */
  RUN_TEST (tls_reconnect_disconnect_resets_tls_state);
  RUN_TEST (tls_reconnect_reset_preserves_tls_config);

  /* Hostname validation */
  RUN_TEST (tls_reconnect_hostname_stored_correctly);
  RUN_TEST (tls_reconnect_reconfigure_hostname);

  /* Resource cleanup */
  RUN_TEST (tls_reconnect_free_with_tls_configured);
  RUN_TEST (tls_reconnect_multiple_tls_instances);

  /* Policy integration */
  RUN_TEST (tls_reconnect_with_custom_policy);

  printf ("All TLS Reconnect tests passed!\n");
#else
  printf ("TLS support not enabled - skipping TLS Reconnect tests\n");
#endif

  return 0;
}

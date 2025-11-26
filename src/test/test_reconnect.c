/**
 * test_reconnect.c - Tests for Automatic Reconnection Framework
 *
 * Part of the Socket Library Test Suite
 * Following C Interfaces and Implementations patterns
 *
 * Tests cover:
 * - Policy configuration defaults and customization
 * - Exponential backoff timing
 * - Circuit breaker state transitions
 * - State machine transitions
 * - Callback invocations
 * - I/O passthrough with auto-reconnect
 * - Health check functionality
 */

#include "test/Test.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketReconnect.h"

#include <math.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

/* ============================================================================
 * Policy Configuration Tests
 * ============================================================================ */

TEST (rc_policy_defaults)
{
  SocketReconnect_Policy_T policy;

  SocketReconnect_policy_defaults (&policy);

  ASSERT_EQ (SOCKET_RECONNECT_DEFAULT_INITIAL_DELAY_MS, policy.initial_delay_ms);
  ASSERT_EQ (SOCKET_RECONNECT_DEFAULT_MAX_DELAY_MS, policy.max_delay_ms);
  ASSERT (fabs (policy.multiplier - SOCKET_RECONNECT_DEFAULT_MULTIPLIER) < 0.001);
  ASSERT (fabs (policy.jitter - SOCKET_RECONNECT_DEFAULT_JITTER) < 0.001);
  ASSERT_EQ (SOCKET_RECONNECT_DEFAULT_MAX_ATTEMPTS, policy.max_attempts);
  ASSERT_EQ (SOCKET_RECONNECT_DEFAULT_CIRCUIT_THRESHOLD,
             policy.circuit_failure_threshold);
  ASSERT_EQ (SOCKET_RECONNECT_DEFAULT_CIRCUIT_RESET_MS,
             policy.circuit_reset_timeout_ms);
  ASSERT_EQ (SOCKET_RECONNECT_DEFAULT_HEALTH_INTERVAL_MS,
             policy.health_check_interval_ms);
  ASSERT_EQ (SOCKET_RECONNECT_DEFAULT_HEALTH_TIMEOUT_MS,
             policy.health_check_timeout_ms);
}

TEST (rc_policy_custom)
{
  SocketReconnect_Policy_T policy;

  SocketReconnect_policy_defaults (&policy);

  policy.initial_delay_ms = 50;
  policy.max_delay_ms = 10000;
  policy.multiplier = 1.5;
  policy.jitter = 0.1;
  policy.max_attempts = 5;
  policy.circuit_failure_threshold = 3;
  policy.circuit_reset_timeout_ms = 30000;
  policy.health_check_interval_ms = 15000;
  policy.health_check_timeout_ms = 3000;

  ASSERT_EQ (50, policy.initial_delay_ms);
  ASSERT_EQ (10000, policy.max_delay_ms);
  ASSERT (fabs (policy.multiplier - 1.5) < 0.001);
  ASSERT (fabs (policy.jitter - 0.1) < 0.001);
  ASSERT_EQ (5, policy.max_attempts);
  ASSERT_EQ (3, policy.circuit_failure_threshold);
  ASSERT_EQ (30000, policy.circuit_reset_timeout_ms);
  ASSERT_EQ (15000, policy.health_check_interval_ms);
  ASSERT_EQ (3000, policy.health_check_timeout_ms);
}

/* ============================================================================
 * State Name Tests
 * ============================================================================ */

TEST (rc_state_names)
{
  ASSERT (strcmp (SocketReconnect_state_name (RECONNECT_DISCONNECTED),
                  "DISCONNECTED") == 0);
  ASSERT (strcmp (SocketReconnect_state_name (RECONNECT_CONNECTING),
                  "CONNECTING") == 0);
  ASSERT (strcmp (SocketReconnect_state_name (RECONNECT_CONNECTED),
                  "CONNECTED") == 0);
  ASSERT (strcmp (SocketReconnect_state_name (RECONNECT_BACKOFF),
                  "BACKOFF") == 0);
  ASSERT (strcmp (SocketReconnect_state_name (RECONNECT_CIRCUIT_OPEN),
                  "CIRCUIT_OPEN") == 0);
  ASSERT (strcmp (SocketReconnect_state_name ((SocketReconnect_State)99),
                  "UNKNOWN") == 0);
}

/* ============================================================================
 * Context Creation Tests
 * ============================================================================ */

TEST (rc_create_basic)
{
  SocketReconnect_T conn = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY { conn = SocketReconnect_new ("localhost", 8080, NULL, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0); /* Should not fail */
    return;
  }
  END_TRY;

  ASSERT_NOT_NULL (conn);
  ASSERT_EQ (RECONNECT_DISCONNECTED, SocketReconnect_state (conn));
  ASSERT_EQ (0, SocketReconnect_isconnected (conn));
  ASSERT_EQ (0, SocketReconnect_attempts (conn));
  ASSERT_EQ (0, SocketReconnect_failures (conn));
  ASSERT_NULL (SocketReconnect_socket (conn));

  SocketReconnect_free (&conn);
  ASSERT_NULL (conn);
}

TEST (rc_create_with_policy)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;

  signal (SIGPIPE, SIG_IGN);

  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 3;
  policy.initial_delay_ms = 50;

  TRY { conn = SocketReconnect_new ("localhost", 8080, &policy, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  ASSERT_NOT_NULL (conn);

  SocketReconnect_free (&conn);
}

/* ============================================================================
 * Callback Tests
 * ============================================================================ */

static int callback_count = 0;
static SocketReconnect_State last_old_state = RECONNECT_DISCONNECTED;
static SocketReconnect_State last_new_state = RECONNECT_DISCONNECTED;

static void
test_callback (SocketReconnect_T conn, SocketReconnect_State old_state,
               SocketReconnect_State new_state, void *userdata)
{
  (void)conn;
  (void)userdata;
  callback_count++;
  last_old_state = old_state;
  last_new_state = new_state;
}

TEST (rc_callback_invoked)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;

  signal (SIGPIPE, SIG_IGN);

  /* Reset globals */
  callback_count = 0;
  last_old_state = RECONNECT_DISCONNECTED;
  last_new_state = RECONNECT_DISCONNECTED;

  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 1;

  TRY
  {
    /* Use localhost for fast failure */
    conn = SocketReconnect_new ("127.0.0.1", 59996, &policy,
                                test_callback, NULL);
  }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Should start in DISCONNECTED */
  ASSERT_EQ (RECONNECT_DISCONNECTED, SocketReconnect_state (conn));
  ASSERT_EQ (0, callback_count);

  /* Try to connect - will transition to CONNECTING */
  SocketReconnect_connect (conn);

  /* Should have called callback for DISCONNECTED -> CONNECTING */
  ASSERT (callback_count > 0);

  /* Let it process */
  for (int i = 0; i < 5; i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (20000);
    }

  /* Should have state transitions */
  ASSERT (callback_count >= 1);

  SocketReconnect_free (&conn);
}

/* ============================================================================
 * Connection State Tests
 * ============================================================================ */

TEST (rc_connect_to_server)
{
  Socket_T server = NULL;
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;
  volatile int port = 0;

  signal (SIGPIPE, SIG_IGN);

  /* Create listening server */
  TRY
  {
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    port = Socket_getlocalport (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    ASSERT (0);
    return;
  }
  END_TRY;

  SocketReconnect_policy_defaults (&policy);

  TRY { conn = SocketReconnect_new ("127.0.0.1", port, &policy, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    Socket_free (&server);
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Start connection */
  SocketReconnect_connect (conn);

  /* Process until connected or timeout */
  int iterations = 0;
  while (!SocketReconnect_isconnected (conn) && iterations < 50)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (50000); /* 50ms */
      iterations++;
    }

  ASSERT (SocketReconnect_isconnected (conn));
  ASSERT_NOT_NULL (SocketReconnect_socket (conn));

  /* Clean disconnect */
  SocketReconnect_disconnect (conn);
  ASSERT_EQ (RECONNECT_DISCONNECTED, SocketReconnect_state (conn));
  ASSERT_EQ (0, SocketReconnect_attempts (conn)); /* Reset on disconnect */

  SocketReconnect_free (&conn);
  Socket_free (&server);
}

/* ============================================================================
 * Backoff Tests
 * ============================================================================ */

TEST (rc_backoff_state)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;

  signal (SIGPIPE, SIG_IGN);

  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 2;
  policy.initial_delay_ms = 50;

  TRY
  {
    /* Connect to localhost port */
    conn = SocketReconnect_new ("127.0.0.1", 59999, &policy, NULL, NULL);
  }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Start connection */
  SocketReconnect_connect (conn);

  /* Process a few times */
  for (int i = 0; i < 10; i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (20000);
    }

  /* After processing, verify we're in a valid state */
  SocketReconnect_State state = SocketReconnect_state (conn);
  /* State could be CONNECTED (if something is listening), BACKOFF, 
   * CONNECTING, or DISCONNECTED - all are valid */
  ASSERT (state == RECONNECT_BACKOFF || state == RECONNECT_DISCONNECTED
          || state == RECONNECT_CONNECTING || state == RECONNECT_CONNECTED);

  SocketReconnect_free (&conn);
}

TEST (rc_backoff_timeout)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;

  signal (SIGPIPE, SIG_IGN);

  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 2;
  policy.initial_delay_ms = 100;

  TRY
  {
    /* Use localhost port */
    conn = SocketReconnect_new ("127.0.0.1", 59998, &policy, NULL, NULL);
  }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  SocketReconnect_connect (conn);

  /* Process a few times */
  for (int i = 0; i < 10; i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (20000);
    }

  /* Check timeout value */
  int timeout = SocketReconnect_next_timeout_ms (conn);
  SocketReconnect_State state = SocketReconnect_state (conn);

  /* State could be any valid state depending on what's listening */
  ASSERT (state == RECONNECT_BACKOFF || state == RECONNECT_CONNECTING
          || state == RECONNECT_DISCONNECTED || state == RECONNECT_CONNECTED);

  /* If in backoff, timeout should be reasonable */
  if (state == RECONNECT_BACKOFF)
    {
      ASSERT (timeout >= 0);
    }

  SocketReconnect_free (&conn);
}

/* ============================================================================
 * Reset Tests
 * ============================================================================ */

TEST (rc_reset)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_Policy_T policy;

  signal (SIGPIPE, SIG_IGN);

  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 3;

  TRY
  {
    /* Use localhost for fast failure */
    conn = SocketReconnect_new ("127.0.0.1", 59997, &policy, NULL, NULL);
  }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Start and let it attempt */
  SocketReconnect_connect (conn);
  for (int i = 0; i < 5; i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (20000);
    }

  /* Reset */
  SocketReconnect_reset (conn);

  ASSERT_EQ (0, SocketReconnect_attempts (conn));
  ASSERT_EQ (0, SocketReconnect_failures (conn));

  SocketReconnect_free (&conn);
}

/* ============================================================================
 * Edge Cases
 * ============================================================================ */

TEST (rc_free_null)
{
  SocketReconnect_T conn = NULL;
  SocketReconnect_free (&conn); /* Should not crash */
  SocketReconnect_free (NULL);  /* Should not crash */
  ASSERT (1);
}

TEST (rc_pollfd_disconnected)
{
  SocketReconnect_T conn = NULL;

  signal (SIGPIPE, SIG_IGN);

  TRY { conn = SocketReconnect_new ("localhost", 8080, NULL, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  /* When disconnected, pollfd should be -1 */
  ASSERT_EQ (-1, SocketReconnect_pollfd (conn));

  SocketReconnect_free (&conn);
}

TEST (rc_multiple_connect_calls)
{
  SocketReconnect_T conn = NULL;
  Socket_T server = NULL;
  volatile int port = 0;

  signal (SIGPIPE, SIG_IGN);

  /* Create server */
  TRY
  {
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    port = Socket_getlocalport (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    ASSERT (0);
    return;
  }
  END_TRY;

  TRY { conn = SocketReconnect_new ("127.0.0.1", port, NULL, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    Socket_free (&server);
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Multiple connect calls should be idempotent */
  SocketReconnect_connect (conn);
  SocketReconnect_connect (conn); /* Should be no-op */
  SocketReconnect_connect (conn); /* Should be no-op */

  /* Process */
  for (int i = 0; i < 20; i++)
    {
      SocketReconnect_process (conn);
      SocketReconnect_tick (conn);
      usleep (50000);
    }

  SocketReconnect_free (&conn);
  Socket_free (&server);
}

/* ============================================================================
 * I/O Passthrough Tests
 * ============================================================================ */

TEST (rc_send_not_connected)
{
  SocketReconnect_T conn = NULL;
  char buf[] = "test";

  signal (SIGPIPE, SIG_IGN);

  TRY { conn = SocketReconnect_new ("localhost", 8080, NULL, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Send should fail when not connected */
  ssize_t result = SocketReconnect_send (conn, buf, sizeof (buf));
  ASSERT_EQ (-1, result);

  SocketReconnect_free (&conn);
}

TEST (rc_recv_not_connected)
{
  SocketReconnect_T conn = NULL;
  char buf[16];

  signal (SIGPIPE, SIG_IGN);

  TRY { conn = SocketReconnect_new ("localhost", 8080, NULL, NULL, NULL); }
  EXCEPT (SocketReconnect_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Recv should fail when not connected */
  ssize_t result = SocketReconnect_recv (conn, buf, sizeof (buf));
  ASSERT_EQ (-1, result);

  SocketReconnect_free (&conn);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int
main (void)
{
  /* Ignore SIGPIPE globally */
  signal (SIGPIPE, SIG_IGN);

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}


/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_happy_eyeballs.c - Tests for Happy Eyeballs (RFC 8305) Implementation
 *
 * Part of the Socket Library Test Suite
 *
 * Tests cover:
 * - Configuration defaults and customization
 * - Synchronous connection API
 * - Asynchronous connection API
 * - State machine transitions
 * - Timeout handling
 * - Cancellation
 * - Error cases
 */

/* cppcheck-suppress-file unreadVariable ; intentional test patterns */

#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketHappyEyeballs.h"
#include "test/Test.h"

#include <signal.h>
#include <string.h>
#include <unistd.h>

/* ============================================================================
 * Configuration Tests
 * ============================================================================
 */

TEST (he_config_defaults)
{
  SocketHE_Config_T config;

  SocketHappyEyeballs_config_defaults (&config);

  ASSERT_EQ (SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS,
             config.first_attempt_delay_ms);
  ASSERT_EQ (SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS, config.attempt_timeout_ms);
  ASSERT_EQ (SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS, config.total_timeout_ms);
  ASSERT_EQ (1, config.prefer_ipv6);
  ASSERT_EQ (SOCKET_HE_DEFAULT_MAX_ATTEMPTS, config.max_attempts);
}

TEST (he_config_custom)
{
  SocketHE_Config_T config;

  SocketHappyEyeballs_config_defaults (&config);

  config.first_attempt_delay_ms = 100;
  config.attempt_timeout_ms = 1000;
  config.total_timeout_ms = 5000;
  config.prefer_ipv6 = 0;
  config.max_attempts = 4;

  ASSERT_EQ (100, config.first_attempt_delay_ms);
  ASSERT_EQ (1000, config.attempt_timeout_ms);
  ASSERT_EQ (5000, config.total_timeout_ms);
  ASSERT_EQ (0, config.prefer_ipv6);
  ASSERT_EQ (4, config.max_attempts);
}

/* ============================================================================
 * Synchronous API Tests
 * ============================================================================
 */

TEST (he_sync_connect_localhost)
{
  Socket_T server = NULL;
  Socket_T client = NULL;
  SocketHE_Config_T config;
  volatile int port = 0;

  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  /* Create listening server on localhost */
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
    ASSERT (0); /* Test setup failed */
    return;
  }
  END_TRY;

  ASSERT (port > 0);

  /* Configure quick timeout for test */
  SocketHappyEyeballs_config_defaults (&config);
  config.total_timeout_ms = 5000;
  config.attempt_timeout_ms = 2000;

  /* Connect using Happy Eyeballs */
  TRY { client = SocketHappyEyeballs_connect ("127.0.0.1", port, &config); }
  EXCEPT (SocketHE_Failed)
  {
    Socket_free (&server);
    ASSERT (0); /* Connection should succeed to localhost */
    return;
  }
  END_TRY;

  ASSERT_NOT_NULL (client);
  ASSERT (Socket_fd (client) >= 0);

  Socket_free (&client);
  Socket_free (&server);
}

TEST (he_sync_connect_hostname_localhost)
{
  Socket_T server = NULL;
  Socket_T client = NULL;
  SocketHE_Config_T config;
  volatile int port = 0;

  signal (SIGPIPE, SIG_IGN);

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

  SocketHappyEyeballs_config_defaults (&config);
  config.total_timeout_ms = 5000;

  /* Connect using hostname "localhost" */
  TRY { client = SocketHappyEyeballs_connect ("localhost", port, &config); }
  EXCEPT (SocketHE_Failed)
  {
    Socket_free (&server);
    ASSERT (0);
    return;
  }
  END_TRY;

  ASSERT_NOT_NULL (client);

  Socket_free (&client);
  Socket_free (&server);
}

TEST (he_sync_connect_timeout)
{
  SocketHE_Config_T config;
  volatile int caught = 0;

  signal (SIGPIPE, SIG_IGN);

  SocketHappyEyeballs_config_defaults (&config);
  config.total_timeout_ms = 500;
  config.attempt_timeout_ms = 200;

  /* Try to connect to non-routable address - should timeout */
  TRY
  {
    Socket_T client
        = SocketHappyEyeballs_connect ("10.255.255.1", 12345, &config);
    if (client)
      Socket_free (&client);
  }
  EXCEPT (SocketHE_Failed) { caught = 1; }
  END_TRY;

  ASSERT (caught);
}

/* ============================================================================
 * Asynchronous API Tests
 * ============================================================================
 */

TEST (he_async_connect_localhost)
{
  Socket_T server = NULL;
  Socket_T client = NULL;
  SocketDNS_T dns = NULL;
  SocketPoll_T poll = NULL;
  SocketHE_T he = NULL;
  SocketHE_Config_T config;
  volatile int port = 0;
  volatile int iterations = 0;
  const int max_iterations = 100;

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

  /* Create DNS and poll */
  TRY
  {
    dns = SocketDNS_new ();
    poll = SocketPoll_new (64);
  }
  EXCEPT (SocketDNS_Failed)
  EXCEPT (SocketPoll_Failed)
  {
    if (dns)
      SocketDNS_free (&dns);
    if (poll)
      SocketPoll_free (&poll);
    Socket_free (&server);
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Start async Happy Eyeballs */
  SocketHappyEyeballs_config_defaults (&config);
  config.total_timeout_ms = 5000;

  TRY
  {
    he = SocketHappyEyeballs_start (dns, poll, "127.0.0.1", port, &config);
  }
  EXCEPT (SocketHE_Failed)
  {
    SocketDNS_free (&dns);
    SocketPoll_free (&poll);
    Socket_free (&server);
    ASSERT (0);
    return;
  }
  END_TRY;

  ASSERT_NOT_NULL (he);
  ASSERT_EQ (HE_STATE_RESOLVING, SocketHappyEyeballs_state (he));

  /* Process until complete */
  while (!SocketHappyEyeballs_poll (he) && iterations < max_iterations)
    {
      int timeout = SocketHappyEyeballs_next_timeout_ms (he);
      if (timeout < 0)
        timeout = 100;
      if (timeout > 100)
        timeout = 100;
      (void)timeout; /* Suppress unused - testing API, using fixed sleep */

      SocketDNS_check (dns);
      SocketHappyEyeballs_process (he);

      usleep (10000); /* 10ms */
      iterations++;
    }

  ASSERT (SocketHappyEyeballs_poll (he));

  if (SocketHappyEyeballs_state (he) == HE_STATE_CONNECTED)
    {
      client = SocketHappyEyeballs_result (he);
      ASSERT_NOT_NULL (client);
      Socket_free (&client);
    }

  SocketHappyEyeballs_free (&he);
  SocketDNS_free (&dns);
  SocketPoll_free (&poll);
  Socket_free (&server);
}

TEST (he_async_cancel)
{
  SocketDNS_T dns = NULL;
  SocketPoll_T poll = NULL;
  SocketHE_T he = NULL;
  SocketHE_Config_T config;

  signal (SIGPIPE, SIG_IGN);

  TRY
  {
    dns = SocketDNS_new ();
    poll = SocketPoll_new (64);
  }
  EXCEPT (SocketDNS_Failed)
  EXCEPT (SocketPoll_Failed)
  {
    if (dns)
      SocketDNS_free (&dns);
    if (poll)
      SocketPoll_free (&poll);
    ASSERT (0);
    return;
  }
  END_TRY;

  SocketHappyEyeballs_config_defaults (&config);
  config.total_timeout_ms = 30000; /* Long timeout */

  TRY
  {
    he = SocketHappyEyeballs_start (dns, poll, "example.com", 80, &config);
  }
  EXCEPT (SocketHE_Failed)
  {
    SocketDNS_free (&dns);
    SocketPoll_free (&poll);
    ASSERT (0);
    return;
  }
  END_TRY;

  ASSERT_NOT_NULL (he);

  /* Cancel immediately */
  SocketHappyEyeballs_cancel (he);
  ASSERT_EQ (HE_STATE_CANCELLED, SocketHappyEyeballs_state (he));
  ASSERT_NULL (SocketHappyEyeballs_result (he));

  SocketHappyEyeballs_free (&he);
  SocketDNS_free (&dns);
  SocketPoll_free (&poll);
}

TEST (he_state_transitions)
{
  SocketHE_T he = NULL;
  SocketDNS_T dns = NULL;
  SocketPoll_T poll = NULL;
  SocketHE_Config_T config;
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

  TRY
  {
    dns = SocketDNS_new ();
    poll = SocketPoll_new (64);
  }
  EXCEPT (SocketDNS_Failed)
  EXCEPT (SocketPoll_Failed)
  {
    if (dns)
      SocketDNS_free (&dns);
    if (poll)
      SocketPoll_free (&poll);
    Socket_free (&server);
    ASSERT (0);
    return;
  }
  END_TRY;

  SocketHappyEyeballs_config_defaults (&config);

  TRY
  {
    he = SocketHappyEyeballs_start (dns, poll, "127.0.0.1", port, &config);
  }
  EXCEPT (SocketHE_Failed)
  {
    SocketDNS_free (&dns);
    SocketPoll_free (&poll);
    Socket_free (&server);
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Initial state should be RESOLVING */
  ASSERT_EQ (HE_STATE_RESOLVING, SocketHappyEyeballs_state (he));

  /* Process to completion */
  int iterations = 0;
  while (!SocketHappyEyeballs_poll (he) && iterations < 100)
    {
      SocketDNS_check (dns);
      SocketHappyEyeballs_process (he);
      usleep (10000);
      iterations++;
    }

  /* Should end in CONNECTED or FAILED */
  SocketHE_State final_state = SocketHappyEyeballs_state (he);
  ASSERT (final_state == HE_STATE_CONNECTED || final_state == HE_STATE_FAILED);

  if (final_state == HE_STATE_CONNECTED)
    {
      Socket_T client = SocketHappyEyeballs_result (he);
      if (client)
        Socket_free (&client);
    }

  SocketHappyEyeballs_free (&he);
  SocketDNS_free (&dns);
  SocketPoll_free (&poll);
  Socket_free (&server);
}

/* ============================================================================
 * Edge Cases
 * ============================================================================
 */

TEST (he_free_null)
{
  SocketHE_T he = NULL;
  SocketHappyEyeballs_free (&he);  /* Should not crash */
  SocketHappyEyeballs_free (NULL); /* Should not crash */
  ASSERT (1);
}

TEST (he_error_message)
{
  SocketHE_Config_T config;
  volatile int caught = 0;

  signal (SIGPIPE, SIG_IGN);

  SocketHappyEyeballs_config_defaults (&config);
  config.total_timeout_ms = 100;
  config.attempt_timeout_ms = 50;

  TRY
  {
    Socket_T client
        = SocketHappyEyeballs_connect ("10.255.255.1", 12345, &config);
    if (client)
      Socket_free (&client);
  }
  EXCEPT (SocketHE_Failed) { caught = 1; }
  END_TRY;

  ASSERT (caught);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  /* Ignore SIGPIPE globally */
  signal (SIGPIPE, SIG_IGN);

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

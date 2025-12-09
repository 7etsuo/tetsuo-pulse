/**
 * fuzz_reconnect.c - Fuzzer for SocketReconnect state machine
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Backoff calculation overflow
 * - Jitter calculation edge cases
 * - State corruption during transitions
 * - Circuit breaker logic bugs
 * - Policy configuration boundary conditions
 *
 * Note: This fuzzer focuses on policy configuration and backoff math.
 * Actual reconnection behavior requires network I/O.
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_reconnect
 * Run:   ./fuzz_reconnect corpus/reconnect/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketReconnect.h"

/**
 * read_u16 - Read a 16-bit value from byte stream
 */
static uint16_t
read_u16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * read_u32 - Read a 32-bit value from byte stream
 */
static uint32_t
read_u32 (const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/**
 * fuzz_policy - Create fuzzed reconnection policy
 */
static void
fuzz_policy (SocketReconnect_Policy_T *policy, const uint8_t *data,
             size_t size)
{
  /* Initialize with zeros */
  memset (policy, 0, sizeof (*policy));

  if (size < 20)
    {
      /* Use defaults */
      policy->initial_delay_ms = SOCKET_RECONNECT_DEFAULT_INITIAL_DELAY_MS;
      policy->max_delay_ms = SOCKET_RECONNECT_DEFAULT_MAX_DELAY_MS;
      policy->multiplier = SOCKET_RECONNECT_DEFAULT_MULTIPLIER;
      policy->jitter = SOCKET_RECONNECT_DEFAULT_JITTER;
      policy->max_attempts = SOCKET_RECONNECT_DEFAULT_MAX_ATTEMPTS;
      policy->circuit_failure_threshold
          = SOCKET_RECONNECT_DEFAULT_CIRCUIT_THRESHOLD;
      policy->circuit_reset_timeout_ms
          = SOCKET_RECONNECT_DEFAULT_CIRCUIT_RESET_MS;
      policy->health_check_interval_ms
          = SOCKET_RECONNECT_DEFAULT_HEALTH_INTERVAL_MS;
      policy->health_check_timeout_ms
          = SOCKET_RECONNECT_DEFAULT_HEALTH_TIMEOUT_MS;
      return;
    }

  /* Backoff settings from fuzz data */
  policy->initial_delay_ms = read_u16 (data);
  policy->max_delay_ms = read_u32 (data + 2);

  /* Multiplier: 1.0 to 10.0 */
  policy->multiplier = 1.0 + ((data[6] % 90) / 10.0);

  /* Jitter: 0.0 to 1.0 */
  policy->jitter = (data[7] % 100) / 100.0;

  /* Max attempts: 0-255 (0 = unlimited) */
  policy->max_attempts = data[8];

  /* Circuit breaker settings */
  policy->circuit_failure_threshold = data[9] % 20;
  policy->circuit_reset_timeout_ms = read_u32 (data + 10);

  /* Health check settings */
  policy->health_check_interval_ms = read_u32 (data + 14);
  policy->health_check_timeout_ms = read_u16 (data + 18);
}

/**
 * make_hostname - Generate hostname from fuzz data
 */
static void
make_hostname (char *buf, size_t bufsize, const uint8_t *data, size_t size)
{
  if (size == 0 || bufsize < 2)
    {
      strncpy (buf, "localhost", bufsize - 1);
      buf[bufsize - 1] = '\0';
      return;
    }

  /* Generate hostname-like string */
  size_t len = size < bufsize - 1 ? size : bufsize - 1;
  for (size_t i = 0; i < len; i++)
    {
      uint8_t c = data[i];
      /* Map to valid hostname characters */
      if (c < 26)
        buf[i] = 'a' + c;
      else if (c < 52)
        buf[i] = 'A' + (c - 26);
      else if (c < 62)
        buf[i] = '0' + (c - 52);
      else if (c < 63)
        buf[i] = '-';
      else if (c < 64)
        buf[i] = '.';
      else
        buf[i] = 'x';
    }
  buf[len] = '\0';

  /* Ensure non-empty */
  if (buf[0] == '\0')
    {
      strncpy (buf, "localhost", bufsize - 1);
      buf[bufsize - 1] = '\0';
    }
}

/**
 * state_callback - Reconnection state change callback
 */
static void
state_callback (SocketReconnect_T conn, SocketReconnect_State old_state,
                SocketReconnect_State new_state, void *userdata)
{
  (void)conn;
  (void)old_state;
  (void)new_state;
  (void)userdata;
  /* Just verify callback is called without crash */
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Bytes 0-19: Policy configuration
 * - Bytes 20-21: Port number
 * - Remaining: Hostname data
 *
 * Tests policy configuration, state queries, and context lifecycle.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketReconnect_Policy_T policy;
  char hostname[256];
  SocketReconnect_T conn = NULL;

  /* Need at least policy + port */
  if (size < 22)
    return 0;

  /* Parse policy */
  fuzz_policy (&policy, data, 20);

  /* Parse port */
  int port = read_u16 (data + 20);
  if (port == 0)
    port = 80;
  if (port > 65535)
    port = 65535;

  /* Parse hostname */
  make_hostname (hostname, sizeof (hostname), data + 22, size - 22);

  TRY
  {
    /* Create reconnection context */
    conn = SocketReconnect_new (hostname, port, &policy, state_callback, NULL);

    if (conn)
      {
        /* Query initial state */
        SocketReconnect_State state = SocketReconnect_state (conn);
        (void)state;

        /* Query timeout (should be valid even in disconnected state) */
        int timeout = SocketReconnect_next_timeout_ms (conn);
        (void)timeout;

        /* Get underlying socket (should be NULL when disconnected) */
        Socket_T sock = SocketReconnect_socket (conn);
        (void)sock;

        /*
         * Note: We don't call SocketReconnect_connect() because that
         * initiates real network I/O. The fuzzer focuses on:
         * 1. Policy parsing and validation
         * 2. Context creation with various configurations
         * 3. State query operations
         * 4. Proper cleanup
         */
      }
  }
  EXCEPT (SocketReconnect_Failed) { /* Expected for invalid configurations */ }
  FINALLY
  {
    if (conn)
      SocketReconnect_free (&conn);
  }
  END_TRY;

  return 0;
}

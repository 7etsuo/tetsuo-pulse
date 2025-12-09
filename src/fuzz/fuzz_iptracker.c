/**
 * fuzz_iptracker.c - Fuzzer for SocketIPTracker hash table
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Hash collision handling
 * - Memory exhaustion from many unique IPs
 * - Rate limit bypass edge cases
 * - Configuration change boundary conditions
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_iptracker
 * Run:   ./fuzz_iptracker corpus/iptracker/ -fork=16 -max_len=8192
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketIPTracker.h"

/* Operation codes for IP tracker fuzzing */
enum IPTrackerOp
{
  IP_TRACK = 0,
  IP_RELEASE,
  IP_COUNT,
  IP_SETMAX,
  IP_GETMAX,
  IP_TOTAL,
  IP_UNIQUE,
  IP_CLEAR,
  IP_OP_COUNT
};

/* Generate IP string from bytes */
static void
make_ipv4 (char *buf, const uint8_t *bytes)
{
  snprintf (buf, 16, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

static void
make_ipv6 (char *buf, const uint8_t *bytes)
{
  snprintf (buf, 40, "%02x%02x:%02x%02x:%02x%02x:%02x%02x::", bytes[0],
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
            bytes[7]);
}

/**
 * execute_op - Execute a single IP tracker operation
 */
static void
execute_op (SocketIPTracker_T tracker, uint8_t op, const uint8_t *args,
            size_t args_len)
{
  char ip_buf[48];

  switch (op % IP_OP_COUNT)
    {
    case IP_TRACK:
      {
        if (args_len < 4)
          break;

        /* Generate IP from args */
        if (args[0] & 1)
          {
            /* IPv4 */
            make_ipv4 (ip_buf, args);
          }
        else if (args_len >= 8)
          {
            /* IPv6 */
            make_ipv6 (ip_buf, args);
          }
        else
          {
            make_ipv4 (ip_buf, args);
          }

        int allowed = SocketIPTracker_track (tracker, ip_buf);
        (void)allowed;
      }
      break;

    case IP_RELEASE:
      {
        if (args_len < 4)
          break;

        /* Generate same IP pattern as track */
        if (args[0] & 1)
          {
            make_ipv4 (ip_buf, args);
          }
        else if (args_len >= 8)
          {
            make_ipv6 (ip_buf, args);
          }
        else
          {
            make_ipv4 (ip_buf, args);
          }

        SocketIPTracker_release (tracker, ip_buf);
      }
      break;

    case IP_COUNT:
      {
        if (args_len < 4)
          break;

        if (args[0] & 1)
          {
            make_ipv4 (ip_buf, args);
          }
        else if (args_len >= 8)
          {
            make_ipv6 (ip_buf, args);
          }
        else
          {
            make_ipv4 (ip_buf, args);
          }

        int count = SocketIPTracker_count (tracker, ip_buf);
        (void)count;
      }
      break;

    case IP_SETMAX:
      {
        int new_max = args_len >= 1 ? args[0] : 10;
        SocketIPTracker_setmax (tracker, new_max);
      }
      break;

    case IP_GETMAX:
      {
        int max = SocketIPTracker_getmax (tracker);
        (void)max;
      }
      break;

    case IP_TOTAL:
      {
        size_t total = SocketIPTracker_total (tracker);
        (void)total;
      }
      break;

    case IP_UNIQUE:
      {
        size_t unique = SocketIPTracker_unique_ips (tracker);
        (void)unique;
      }
      break;

    case IP_CLEAR:
      {
        SocketIPTracker_clear (tracker);
      }
      break;
    }
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Initial max_per_ip
 * - Remaining: Sequence of (op, args...) operations
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketIPTracker_T tracker = NULL;

  /* Need at least config + one operation */
  if (size < 2)
    return 0;

  /* Parse initial configuration */
  int max_per_ip = data[0]; /* 0-255 (0 = unlimited) */

  const uint8_t *stream = data + 1;
  size_t stream_len = size - 1;

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      return 0;

    tracker = SocketIPTracker_new (arena, max_per_ip);
    if (!tracker)
      {
        Arena_dispose (&arena);
        return 0;
      }

    /* Execute operation sequence */
    size_t i = 0;
    while (i < stream_len)
      {
        uint8_t op = stream[i++];
        const uint8_t *args = stream + i;
        size_t args_len = stream_len - i;

        execute_op (tracker, op, args, args_len);

        /* Consume argument bytes based on operation */
        size_t consume = 1;
        if (op % IP_OP_COUNT <= IP_COUNT)
          consume = 4; /* IP operations need 4 bytes */
        i += consume;
      }

    /* Final state verification */
    (void)SocketIPTracker_total (tracker);
    (void)SocketIPTracker_unique_ips (tracker);
  }
  EXCEPT (Arena_Failed) { /* Memory allocation failure */ }
  EXCEPT (SocketIPTracker_Failed) { /* IP tracker operation failure */ }
  FINALLY
  {
    if (tracker)
      SocketIPTracker_free (&tracker);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}

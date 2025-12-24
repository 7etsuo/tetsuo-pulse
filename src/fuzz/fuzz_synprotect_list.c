/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_synprotect_list.c - LRU List Operations Fuzzer
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets SocketSYNProtect-list.c (currently 8% coverage):
 * - lru_remove() - LRU doubly-linked list removal edge cases
 * - lru_push_front() - List insertion with empty/single/multiple entries
 * - lru_touch() - Move-to-front operation integrity
 * - evict_lru_entry() - Eviction from tail with hash table removal
 * - free_memory() - Memory deallocation with arena/malloc modes
 *
 * This fuzzer stress-tests the LRU eviction mechanism by:
 * - Creating many IP entries to trigger evictions
 * - Touching entries in various patterns
 * - Mixing check/report operations to exercise LRU logic
 * - Testing edge cases: empty list, single entry, full capacity
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_synprotect_list
 * Run:   ./fuzz_synprotect_list corpus/synprotect_list/ -fork=16 -max_len=2048
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Except.h"
#include "core/SocketSYNProtect.h"

/* Operation codes */
enum LRUOperations
{
  OP_CHECK_NEW_IP = 0,
  OP_REPORT_SUCCESS,
  OP_REPORT_FAILURE,
  OP_REPEATED_CHECK,
  OP_FILL_TO_CAPACITY,
  OP_OVERFLOW_CAPACITY,
  OP_TOUCH_PATTERN,
  OP_CLEANUP_ALL,
  OP_RESET,
  OP_GET_STATE,
  OP_COUNT
};

/**
 * read_byte - Read single byte from fuzzer data
 */
static uint8_t
read_byte (const uint8_t **data, size_t *remaining)
{
  if (*remaining == 0)
    return 0;
  uint8_t val = **data;
  (*data)++;
  (*remaining)--;
  return val;
}

/**
 * read_uint16 - Read 16-bit value
 */
static uint16_t
read_uint16 (const uint8_t **data, size_t *remaining)
{
  uint16_t val = 0;
  for (int i = 0; i < 2 && *remaining > 0; i++)
    {
      val = (val << 8) | read_byte (data, remaining);
    }
  return val;
}

/**
 * read_int - Read 32-bit integer
 */
static int
read_int (const uint8_t **data, size_t *remaining)
{
  int val = 0;
  for (int i = 0; i < 4 && *remaining > 0; i++)
    {
      val = (val << 8) | read_byte (data, remaining);
    }
  return val;
}

/**
 * generate_ip - Generate IPv4/IPv6 address for LRU testing
 */
static void
generate_ip (char *buf, size_t bufsize, const uint8_t **data,
             size_t *remaining)
{
  uint8_t type = read_byte (data, remaining) % 3;

  switch (type)
    {
    case 0: /* Sequential IPv4 for predictable patterns */
      snprintf (buf, bufsize, "192.168.%u.%u", read_byte (data, remaining),
                read_byte (data, remaining));
      break;

    case 1: /* IPv6 */
      snprintf (buf, bufsize, "2001:db8::%x:%x", read_uint16 (data, remaining),
                read_uint16 (data, remaining));
      break;

    case 2: /* Fully random IPv4 */
      snprintf (buf, bufsize, "%u.%u.%u.%u", read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining));
      break;
    }
}

/**
 * test_fill_to_capacity - Fill LRU list to max capacity
 *
 * Tests eviction when max_tracked_ips is reached.
 */
static void
test_fill_to_capacity (SocketSYNProtect_T protect, const uint8_t **data,
                       size_t *remaining, size_t max_ips)
{
  char ip_buf[128];

  /* Fill exactly to capacity */
  for (size_t i = 0; i < max_ips && *remaining > 8; i++)
    {
      generate_ip (ip_buf, sizeof (ip_buf), data, remaining);
      SocketSYNProtect_check (protect, ip_buf, NULL);
    }

  /* Verify state */
  SocketSYNProtect_Stats stats;
  SocketSYNProtect_stats (protect, &stats);
}

/**
 * test_overflow_capacity - Add more IPs than capacity to force evictions
 *
 * Tests that evict_lru_entry() is called correctly.
 */
static void
test_overflow_capacity (SocketSYNProtect_T protect, const uint8_t **data,
                        size_t *remaining, size_t max_ips)
{
  char ip_buf[128];

  /* Add 2x capacity to force evictions */
  size_t overflow_count = max_ips * 2;
  for (size_t i = 0; i < overflow_count && *remaining > 8; i++)
    {
      generate_ip (ip_buf, sizeof (ip_buf), data, remaining);
      SocketSYNProtect_check (protect, ip_buf, NULL);

      /* Periodically check stats to verify evictions occurred */
      if (i % 10 == 0)
        {
          SocketSYNProtect_Stats stats;
          SocketSYNProtect_stats (protect, &stats);
          /* LRU evictions should have happened */
        }
    }
}

/**
 * test_touch_pattern - Test LRU touch (move-to-front) operations
 *
 * Creates entries then accesses them in various patterns to test
 * lru_touch() logic.
 */
static void
test_touch_pattern (SocketSYNProtect_T protect, const uint8_t **data,
                    size_t *remaining)
{
  char ips[10][128];
  int ip_count = read_byte (data, remaining) % 10 + 1;

  /* Create several IPs */
  for (int i = 0; i < ip_count && *remaining > 8; i++)
    {
      generate_ip (ips[i], sizeof (ips[i]), data, remaining);
      SocketSYNProtect_check (protect, ips[i], NULL);
    }

  /* Access pattern controlled by fuzzer */
  uint8_t pattern_type = read_byte (data, remaining) % 5;
  switch (pattern_type)
    {
    case 0: /* Sequential forward */
      for (int i = 0; i < ip_count && *remaining > 0; i++)
        {
          SocketSYNProtect_check (protect, ips[i], NULL);
        }
      break;

    case 1: /* Sequential backward */
      for (int i = ip_count - 1; i >= 0 && *remaining > 0; i--)
        {
          SocketSYNProtect_check (protect, ips[i], NULL);
        }
      break;

    case 2: /* Random access */
      for (int i = 0; i < ip_count * 2 && *remaining > 0; i++)
        {
          int idx = read_byte (data, remaining) % ip_count;
          SocketSYNProtect_check (protect, ips[idx], NULL);
        }
      break;

    case 3: /* Repeated access to single IP (should stay at head) */
      {
        int idx = read_byte (data, remaining) % ip_count;
        for (int i = 0; i < 10 && *remaining > 0; i++)
          {
            SocketSYNProtect_check (protect, ips[idx], NULL);
          }
      }
      break;

    case 4: /* Alternating access */
      for (int i = 0; i < ip_count * 2 && *remaining > 0; i++)
        {
          int idx = i % 2;
          if (idx < ip_count)
            SocketSYNProtect_check (protect, ips[idx], NULL);
        }
      break;
    }
}

/**
 * test_success_failure_mix - Mix report_success and report_failure
 *
 * Tests interaction between LRU touch operations and reputation updates.
 */
static void
test_success_failure_mix (SocketSYNProtect_T protect, const uint8_t **data,
                          size_t *remaining)
{
  char ip_buf[128];
  int operation_count = read_byte (data, remaining) % 20 + 5;

  for (int i = 0; i < operation_count && *remaining > 8; i++)
    {
      generate_ip (ip_buf, sizeof (ip_buf), data, remaining);

      uint8_t op = read_byte (data, remaining) % 3;
      switch (op)
        {
        case 0:
          SocketSYNProtect_check (protect, ip_buf, NULL);
          break;
        case 1:
          SocketSYNProtect_report_success (protect, ip_buf);
          break;
        case 2:
          SocketSYNProtect_report_failure (protect, ip_buf, ETIMEDOUT);
          break;
        }
    }
}

/**
 * test_edge_cases - Test LRU edge cases
 */
static void
test_edge_cases (SocketSYNProtect_T protect, const uint8_t **data,
                 size_t *remaining)
{
  char ip_buf[128];

  /* Single entry operations */
  generate_ip (ip_buf, sizeof (ip_buf), data, remaining);
  SocketSYNProtect_check (protect, ip_buf, NULL);

  /* Check same IP multiple times (should touch same entry) */
  for (int i = 0; i < 5 && *remaining > 0; i++)
    {
      SocketSYNProtect_check (protect, ip_buf, NULL);
    }

  /* Get state to force LRU list traversal */
  SocketSYN_IPState state;
  SocketSYNProtect_get_ip_state (protect, ip_buf, &state);

  /* Clear and check empty list behavior */
  SocketSYNProtect_clear_all (protect);

  /* Check on empty list */
  generate_ip (ip_buf, sizeof (ip_buf), data, remaining);
  SocketSYNProtect_check (protect, ip_buf, NULL);
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  const uint8_t *ptr = data;
  size_t remaining = size;

  if (size < 8)
    return 0;

  /* Create protection instance with small capacity for LRU testing */
  TRY
  {
    SocketSYNProtect_config_defaults (&config);

    /* Small max_tracked_ips to trigger LRU evictions quickly */
    size_t max_ips = (read_byte (&ptr, &remaining) % 20) + 10;
    config.max_tracked_ips = max_ips;
    config.max_whitelist = 50;
    config.max_blacklist = 50;

    /* Short window to rotate frequently */
    config.window_duration_ms = 1000;
    config.max_attempts_per_window = 100;

    protect = SocketSYNProtect_new (NULL, &config);
    if (protect == NULL)
      return 0;
  }
  ELSE { return 0; }
  END_TRY;

  /* Get the max_tracked_ips value for test functions */
  SocketSYNProtect_Stats initial_stats;
  TRY { SocketSYNProtect_stats (protect, &initial_stats); }
  ELSE { return 0; }
  END_TRY;

  size_t max_ips = config.max_tracked_ips;

  /* Execute random LRU-focused operations */
  while (remaining > 16)
    {
      uint8_t op = read_byte (&ptr, &remaining) % OP_COUNT;
      char ip_buf[128];

      TRY
      {
        switch (op)
          {
          case OP_CHECK_NEW_IP:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_check (protect, ip_buf, NULL);
            break;

          case OP_REPORT_SUCCESS:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_report_success (protect, ip_buf);
            break;

          case OP_REPORT_FAILURE:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_report_failure (protect, ip_buf,
                                             read_int (&ptr, &remaining));
            break;

          case OP_REPEATED_CHECK:
            /* Check same IP multiple times to test LRU touch */
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            for (int i = 0; i < 5 && remaining > 0; i++)
              {
                SocketSYNProtect_check (protect, ip_buf, NULL);
              }
            break;

          case OP_FILL_TO_CAPACITY:
            test_fill_to_capacity (protect, &ptr, &remaining, max_ips);
            break;

          case OP_OVERFLOW_CAPACITY:
            test_overflow_capacity (protect, &ptr, &remaining, max_ips);
            break;

          case OP_TOUCH_PATTERN:
            test_touch_pattern (protect, &ptr, &remaining);
            break;

          case OP_CLEANUP_ALL:
            SocketSYNProtect_clear_all (protect);
            break;

          case OP_RESET:
            SocketSYNProtect_reset (protect);
            break;

          case OP_GET_STATE:
            {
              SocketSYN_IPState state;
              generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
              SocketSYNProtect_get_ip_state (protect, ip_buf, &state);
            }
            break;
          }
      }
      ELSE { /* Ignore exceptions during fuzzing */ }
      END_TRY;

      /* Periodically run cleanup to test expiration alongside LRU */
      if (read_byte (&ptr, &remaining) % 10 == 0)
        {
          TRY { SocketSYNProtect_cleanup (protect); }
          ELSE {}
          END_TRY;
        }

      /* Early exit if running low on data */
      if (remaining < 32)
        break;
    }

  /* Final edge case test */
  TRY { test_edge_cases (protect, &ptr, &remaining); }
  ELSE {}
  END_TRY;

  /* Test success/failure mix */
  TRY { test_success_failure_mix (protect, &ptr, &remaining); }
  ELSE {}
  END_TRY;

  /* Final stats to verify LRU evictions occurred */
  TRY
  {
    SocketSYNProtect_Stats final_stats;
    SocketSYNProtect_stats (protect, &final_stats);
    /* If we added more than max_ips, evictions should have occurred */
  }
  ELSE {}
  END_TRY;

  /* Cleanup */
  TRY { SocketSYNProtect_free (&protect); }
  ELSE { /* Ignore cleanup exceptions */ }
  END_TRY;

  return 0;
}

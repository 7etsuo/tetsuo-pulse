/**
 * fuzz_synprotect.c - SYN Flood Protection Fuzzing Harness
 *
 * Part of the Socket Library
 *
 * Fuzzes the SYN flood protection module with random:
 * - IP address strings (including malformed)
 * - CIDR notations
 * - Configuration values
 * - Operation sequences
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSYNProtect.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libFuzzer entry point */
int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

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
 * read_int - Read integer from fuzzer data
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
 * read_string - Read null-terminated string from fuzzer data
 * @buf: Output buffer
 * @bufsize: Buffer size
 * @data: Fuzzer data pointer (updated)
 * @remaining: Remaining bytes (updated)
 *
 * Returns: Length of string read
 */
static size_t
read_string (char *buf, size_t bufsize, const uint8_t **data, size_t *remaining)
{
  size_t len = 0;

  while (len < bufsize - 1 && *remaining > 0)
    {
      uint8_t c = read_byte (data, remaining);
      if (c == 0)
        break;
      buf[len++] = (char)c;
    }

  buf[len] = '\0';
  return len;
}

/**
 * generate_random_ip - Generate IP string from fuzzer data
 * @buf: Output buffer
 * @bufsize: Buffer size
 * @data: Fuzzer data
 * @remaining: Remaining bytes
 */
static void
generate_random_ip (char *buf, size_t bufsize, const uint8_t **data,
                    size_t *remaining)
{
  uint8_t type = read_byte (data, remaining) % 5;

  switch (type)
    {
    case 0: /* Valid IPv4 */
      snprintf (buf, bufsize, "%u.%u.%u.%u", read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining));
      break;

    case 1: /* Valid IPv6 */
      snprintf (buf, bufsize, "%x:%x:%x:%x:%x:%x:%x:%x",
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining));
      break;

    case 2: /* Random string (may be invalid) */
      read_string (buf, bufsize, data, remaining);
      break;

    case 3: /* Empty string */
      buf[0] = '\0';
      break;

    case 4: /* Very long string */
      for (size_t i = 0; i < bufsize - 1; i++)
        buf[i] = 'A' + (read_byte (data, remaining) % 26);
      buf[bufsize - 1] = '\0';
      break;
    }
}

/**
 * generate_cidr - Generate CIDR notation from fuzzer data
 */
static void
generate_cidr (char *buf, size_t bufsize, const uint8_t **data, size_t *remaining)
{
  uint8_t type = read_byte (data, remaining) % 4;

  switch (type)
    {
    case 0: /* Valid IPv4 CIDR */
      snprintf (buf, bufsize, "%u.%u.%u.%u/%u", read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining),
                (unsigned)(read_byte (data, remaining) % 33));
      break;

    case 1: /* Valid IPv6 CIDR */
      snprintf (buf, bufsize, "%x:%x::%x/%u", read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                (unsigned)(read_byte (data, remaining) % 129));
      break;

    case 2: /* Invalid CIDR */
      read_string (buf, bufsize, data, remaining);
      break;

    case 3: /* Missing prefix */
      generate_random_ip (buf, bufsize, data, remaining);
      break;
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  char ip_buf[128];
  char cidr_buf[128];
  const uint8_t *ptr = data;
  size_t remaining = size;

  if (size < 4)
    return 0;

  /* Create protection instance with fuzzed config */
  TRY
  {
    SocketSYNProtect_config_defaults (&config);

    /* Fuzz some config values */
    config.window_duration_ms = read_int (&ptr, &remaining) % 100000;
    config.max_attempts_per_window = read_int (&ptr, &remaining) % 1000;
    config.block_duration_ms = read_int (&ptr, &remaining) % 100000;

    protect = SocketSYNProtect_new (NULL, &config);
    if (protect == NULL)
      return 0;
  }
  ELSE { return 0; }
  END_TRY;

  /* Perform random operations */
  while (remaining > 0)
    {
      uint8_t op = read_byte (&ptr, &remaining) % 12;

      TRY
      {
        switch (op)
          {
          case 0: /* Check IP */
            generate_random_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_check (protect, ip_buf, NULL);
            break;

          case 1: /* Check with state */
            {
              SocketSYN_IPState state;
              generate_random_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
              SocketSYNProtect_check (protect, ip_buf, &state);
            }
            break;

          case 2: /* Report success */
            generate_random_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_report_success (protect, ip_buf);
            break;

          case 3: /* Report failure */
            generate_random_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_report_failure (protect, ip_buf,
                                             read_int (&ptr, &remaining));
            break;

          case 4: /* Whitelist add */
            generate_random_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_whitelist_add (protect, ip_buf);
            break;

          case 5: /* Whitelist CIDR */
            generate_cidr (cidr_buf, sizeof (cidr_buf), &ptr, &remaining);
            SocketSYNProtect_whitelist_add_cidr (protect, cidr_buf);
            break;

          case 6: /* Whitelist remove */
            generate_random_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_whitelist_remove (protect, ip_buf);
            break;

          case 7: /* Blacklist add */
            generate_random_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_blacklist_add (protect, ip_buf,
                                            read_int (&ptr, &remaining) % 60000);
            break;

          case 8: /* Blacklist remove */
            generate_random_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_blacklist_remove (protect, ip_buf);
            break;

          case 9: /* Get IP state */
            {
              SocketSYN_IPState state;
              generate_random_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
              SocketSYNProtect_get_ip_state (protect, ip_buf, &state);
            }
            break;

          case 10: /* Cleanup */
            SocketSYNProtect_cleanup (protect);
            break;

          case 11: /* Stats */
            {
              SocketSYNProtect_Stats stats;
              SocketSYNProtect_stats (protect, &stats);
            }
            break;
          }
      }
      ELSE
      {
        /* Ignore exceptions during fuzzing */
      }
      END_TRY;
    }

  /* Cleanup */
  TRY { SocketSYNProtect_free (&protect); }
  ELSE
  { /* Ignore cleanup exceptions */
  }
  END_TRY;

  return 0;
}


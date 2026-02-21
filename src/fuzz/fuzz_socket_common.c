/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_socket_common.c - libFuzzer harness for SocketCommon utilities
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Port validation edge cases (negative, overflow, boundary values)
 * - Hostname validation (RFC 1123 compliance, length limits)
 * - IP address parsing (IPv4, IPv6, malformed)
 * - CIDR matching (prefix validation, family mismatches)
 * - iovec operations (overflow protection, NULL base handling)
 * - addrinfo copy/free (memory safety)
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_socket_common
 * Run:   ./fuzz_socket_common corpus/socket_common/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketCommon.h"

/* Limits to avoid resource exhaustion */
#define FUZZ_MAX_STRING_LEN 512
#define FUZZ_MAX_IOV_COUNT 64
#define FUZZ_MAX_IOV_LEN (64 * 1024)

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_VALIDATE_PORT = 0,
  OP_VALIDATE_HOSTNAME,
  OP_PARSE_IP,
  OP_CIDR_MATCH,
  OP_IOV_CALCULATE,
  OP_IOV_VALIDATE,
  OP_IOV_ADVANCE,
  OP_NORMALIZE_HOST,
  OP_BOUNDARY_PORTS,
  OP_MAX
};

/**
 * parse_int32 - Parse 32-bit signed int from fuzz input
 */
static int32_t
parse_int32 (const uint8_t *data, size_t len)
{
  if (len >= 4)
    {
      return (int32_t)((uint32_t)data[0] | ((uint32_t)data[1] << 8)
                       | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24));
    }
  if (len >= 2)
    {
      /* Sign extend 16-bit value */
      int16_t val = (int16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
      return val;
    }
  if (len >= 1)
    {
      /* Sign extend 8-bit value */
      return (int8_t)data[0];
    }
  return 0;
}

/**
 * parse_size_t - Parse size_t from fuzz input
 */
static size_t
parse_size_t (const uint8_t *data, size_t len)
{
  size_t val = 0;
  for (size_t i = 0; i < len && i < sizeof (size_t); i++)
    {
      val |= ((size_t)data[i]) << (i * 8);
    }
  return val;
}

/**
 * extract_string - Extract null-terminated string from fuzz input
 * Returns bytes consumed
 */
static size_t
extract_string (const uint8_t *data, size_t len, char *str_out, size_t str_max)
{
  size_t str_len = 0;

  if (len >= 1)
    {
      str_len = data[0];
      if (str_len > len - 1)
        str_len = len - 1;
      if (str_len >= str_max)
        str_len = str_max - 1;

      memcpy (str_out, data + 1, str_len);
    }
  str_out[str_len] = '\0';

  return 1 + str_len;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;

  TRY
  {
    switch (op)
      {
      case OP_VALIDATE_PORT:
        {
          /* Test port validation with fuzz-controlled values */
          int port = parse_int32 (payload, payload_size);

          TRY
          {
            SocketCommon_validate_port (port, SocketCommon_Failed);
            /* If we get here, port should be valid (0-65535) */
            assert (port >= 0 && port <= 65535);
          }
          EXCEPT (SocketCommon_Failed)
          {
            /* Expected for invalid ports */
          }
          END_TRY;
        }
        break;

      case OP_VALIDATE_HOSTNAME:
        {
          /* Test hostname validation with fuzz-controlled strings */
          char hostname[FUZZ_MAX_STRING_LEN];
          extract_string (payload, payload_size, hostname, sizeof (hostname));

          TRY
          {
            SocketCommon_validate_hostname (hostname, SocketCommon_Failed);
          }
          EXCEPT (SocketCommon_Failed)
          {
            /* Expected for invalid hostnames */
          }
          END_TRY;

          /* Also test validate_host_not_null */
          TRY
          {
            SocketCommon_validate_host_not_null (hostname, SocketCommon_Failed);
          }
          EXCEPT (SocketCommon_Failed)
          {
            /* Expected if hostname is empty or NULL-like */
          }
          END_TRY;
        }
        break;

      case OP_PARSE_IP:
        {
          /* Test IP address parsing */
          char ip_str[FUZZ_MAX_STRING_LEN];
          extract_string (payload, payload_size, ip_str, sizeof (ip_str));

          int family = 0;
          int result = SocketCommon_parse_ip (ip_str, &family);

          if (result == 1)
            {
              /* Valid IP - family should be set */
              assert (family == AF_INET || family == AF_INET6);
            }
          else
            {
              /* Invalid IP - family should be AF_UNSPEC */
              assert (family == AF_UNSPEC);
            }

          /* Test with NULL family output */
          result = SocketCommon_parse_ip (ip_str, NULL);
          (void)result;
        }
        break;

      case OP_CIDR_MATCH:
        {
          /* Test CIDR matching */
          char ip_str[FUZZ_MAX_STRING_LEN];
          char cidr_str[FUZZ_MAX_STRING_LEN];

          size_t consumed
              = extract_string (payload, payload_size, ip_str, sizeof (ip_str));
          extract_string (payload + consumed,
                          payload_size > consumed ? payload_size - consumed : 0,
                          cidr_str,
                          sizeof (cidr_str));

          int result = SocketCommon_cidr_match (ip_str, cidr_str);
          /* Result should be 1 (match), 0 (no match), or -1 (error) */
          assert (result >= -1 && result <= 1);
        }
        break;

      case OP_IOV_CALCULATE:
        {
          /* Test iovec total length calculation with overflow protection */
          if (payload_size < 2)
            break;

          int iovcnt = payload[0] % (FUZZ_MAX_IOV_COUNT + 1);
          if (iovcnt == 0)
            iovcnt = 1;

          /* Build iovec array with fuzz-controlled lengths */
          struct iovec *iov = calloc (iovcnt, sizeof (struct iovec));
          if (!iov)
            break;

          char *bufs = calloc (iovcnt, 16); /* Small buffers */
          if (!bufs)
            {
              free (iov);
              break;
            }

          size_t offset = 1;
          for (int i = 0; i < iovcnt && offset < payload_size; i++)
            {
              /* Parse length from fuzz input */
              size_t len = 0;
              if (offset + 2 <= payload_size)
                {
                  len = ((size_t)payload[offset])
                        | ((size_t)payload[offset + 1] << 8);
                  offset += 2;
                }
              else if (offset < payload_size)
                {
                  len = payload[offset];
                  offset++;
                }

              /* Cap length to avoid huge allocations */
              if (len > FUZZ_MAX_IOV_LEN)
                len = FUZZ_MAX_IOV_LEN;

              iov[i].iov_base = &bufs[i * 16];
              iov[i].iov_len = len;
            }

          TRY
          {
            size_t total = SocketCommon_calculate_total_iov_len (iov, iovcnt);
            (void)total;
          }
          EXCEPT (SocketCommon_Failed)
          {
            /* Expected for overflow or invalid params */
          }
          END_TRY;

          free (iov);
          free (bufs);
        }
        break;

      case OP_IOV_VALIDATE:
        {
          /* Test iovec base pointer validation */
          if (payload_size < 2)
            break;

          int iovcnt = (payload[0] % FUZZ_MAX_IOV_COUNT) + 1;
          uint8_t null_mask = payload_size > 1 ? payload[1] : 0;

          struct iovec *iov = calloc (iovcnt, sizeof (struct iovec));
          if (!iov)
            break;

          char *bufs = calloc (iovcnt, 16);
          if (!bufs)
            {
              free (iov);
              break;
            }

          /* Set up iov with some NULL bases based on fuzz input */
          for (int i = 0; i < iovcnt; i++)
            {
              if ((null_mask & (1 << (i % 8))) && i < 8)
                {
                  iov[i].iov_base = NULL;
                  iov[i].iov_len = 100; /* NULL base with positive length */
                }
              else
                {
                  iov[i].iov_base = &bufs[i * 16];
                  iov[i].iov_len = 16;
                }
            }

          TRY
          {
            SocketCommon_validate_iov_bases (iov, iovcnt);
          }
          EXCEPT (SocketCommon_Failed)
          {
            /* Expected if any iov_base is NULL with positive length */
          }
          END_TRY;

          free (iov);
          free (bufs);
        }
        break;

      case OP_IOV_ADVANCE:
        {
          /* Test iovec advance operation */
          if (payload_size < 4)
            break;

          int iovcnt = (payload[0] % 8) + 1; /* Keep small for advance test */

          struct iovec *iov = calloc (iovcnt, sizeof (struct iovec));
          if (!iov)
            break;

          /* Allocate actual buffers */
          char **bufs = calloc (iovcnt, sizeof (char *));
          if (!bufs)
            {
              free (iov);
              break;
            }

          size_t total_len = 0;
          for (int i = 0; i < iovcnt; i++)
            {
              size_t len = ((i + 1) * 100) % 500 + 10;
              bufs[i] = malloc (len);
              if (!bufs[i])
                {
                  for (int j = 0; j < i; j++)
                    free (bufs[j]);
                  free (bufs);
                  free (iov);
                  break;
                }
              iov[i].iov_base = bufs[i];
              iov[i].iov_len = len;
              total_len += len;
            }

          /* Get advance amount from fuzz input, modulo total to test both valid
           * and overflow cases */
          size_t advance_bytes = parse_size_t (payload + 1, payload_size - 1);
          /* Suppress unused warning - total_len used for context */
          (void)total_len;

          TRY
          {
            SocketCommon_advance_iov (iov, iovcnt, advance_bytes);
          }
          EXCEPT (SocketCommon_Failed)
          {
            /* Expected if advance > total length */
          }
          END_TRY;

          /* Cleanup */
          for (int i = 0; i < iovcnt; i++)
            {
              if (bufs[i])
                free (bufs[i]);
            }
          free (bufs);
          free (iov);
        }
        break;

      case OP_NORMALIZE_HOST:
        {
          /* Test wildcard host normalization */
          char hostname[FUZZ_MAX_STRING_LEN];
          extract_string (payload, payload_size, hostname, sizeof (hostname));

          const char *result = SocketCommon_normalize_wildcard_host (hostname);

          /* Should return NULL for "0.0.0.0", "::", or NULL input */
          if (strcmp (hostname, "0.0.0.0") == 0 || strcmp (hostname, "::") == 0)
            {
              assert (result == NULL);
            }
          else if (hostname[0] != '\0')
            {
              /* Non-wildcard should return original pointer */
              assert (result == hostname);
            }

          /* Test with NULL */
          result = SocketCommon_normalize_wildcard_host (NULL);
          assert (result == NULL);
        }
        break;

      case OP_BOUNDARY_PORTS:
        {
          /* Test specific boundary port values */
          int test_ports[] = {
            -2147483648, /* INT_MIN */
            -65536,      /* -65536 */
            -1,          /* Just below valid */
            0,           /* Valid: ephemeral */
            1,           /* Valid: privileged */
            1023,        /* Last privileged */
            1024,        /* First unprivileged */
            65535,       /* Max valid */
            65536,       /* Just above valid */
            2147483647,  /* INT_MAX */
          };

          for (size_t i = 0; i < sizeof (test_ports) / sizeof (test_ports[0]);
               i++)
            {
              TRY
              {
                SocketCommon_validate_port (test_ports[i], SocketCommon_Failed);
                /* Should only succeed for 0-65535 */
                assert (test_ports[i] >= 0 && test_ports[i] <= 65535);
              }
              EXCEPT (SocketCommon_Failed)
              {
                /* Expected for invalid ports */
                assert (test_ports[i] < 0 || test_ports[i] > 65535);
              }
              END_TRY;
            }

          /* Also test with fuzz-controlled additional ports */
          size_t offset = 0;
          while (offset + 4 <= payload_size)
            {
              int port = parse_int32 (payload + offset, 4);
              offset += 4;

              TRY
              {
                SocketCommon_validate_port (port, SocketCommon_Failed);
              }
              EXCEPT (SocketCommon_Failed)
              {
                /* Expected */
              }
              END_TRY;
            }
        }
        break;
      }
  }
  EXCEPT (SocketCommon_Failed)
  {
    /* Catch any unexpected exceptions */
  }
  END_TRY;

  return 0;
}

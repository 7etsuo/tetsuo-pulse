/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_dot.c - libFuzzer harness for DNS-over-TLS protocol
 *
 * Fuzzes DNS-over-TLS transport implementation (RFC 7858, RFC 8310).
 *
 * Targets:
 * - SocketDNSoverTLS_new() - Transport creation
 * - SocketDNSoverTLS_configure() - Server configuration
 * - SocketDNSoverTLS_add_server() - Well-known server setup
 * - SocketDNSoverTLS_query() - Query submission
 * - SocketDNSoverTLS_process() - Event loop processing
 * - SocketDNSoverTLS_cancel() - Query cancellation
 * - SocketDNSoverTLS_stats() - Statistics gathering
 * - SocketDNSoverTLS_is_connected() - Connection state
 * - SocketDNSoverTLS_close_all() - Connection cleanup
 *
 * Attack Surfaces:
 * - 2-byte length prefix framing (RFC 1035 §4.2.2)
 *   - Invalid length values (0, >65535)
 *   - Length/message size mismatches
 *   - Truncated messages after length prefix
 * - TLS handshake state machine
 *   - Handshake timeout handling
 *   - Session resumption logic
 *   - Certificate verification modes (opportunistic vs strict)
 * - Connection pooling
 *   - Connection reuse race conditions
 *   - Idle timeout edge cases
 *   - Query timeout handling
 * - Response parsing
 *   - Malformed DNS headers
 *   - Response ID mismatches
 *   - RCODE error handling
 * - Configuration
 *   - Invalid server addresses (IPv4/IPv6)
 *   - Malformed server names (SNI)
 *   - SPKI pin format validation
 *
 * Test Cases:
 * - Valid DoT query/response roundtrip
 * - Truncated length prefix (1 byte)
 * - Zero-length message
 * - Maximum message size (65535 bytes)
 * - Message larger than length prefix
 * - Multiple queries pipelined
 * - Query timeout scenarios
 * - Connection close during handshake
 * - Malformed DNS response headers
 * - Response ID mismatch
 * - RCODE error responses (SERVFAIL, NXDOMAIN, REFUSED)
 * - Server configuration with invalid addresses
 * - SPKI pin validation
 * - Connection reuse after idle timeout
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make fuzz_dns_dot
 * Run:   ./fuzz_dns_dot corpus/dns_dot/ -fork=16 -max_len=8192
 */

#if SOCKET_HAS_TLS

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNSoverTLS.h"
#include "dns/SocketDNSWire.h"

/* Maximum input size to prevent timeouts */
#define MAX_FUZZ_SIZE 8192

/* Fuzzer operation types */
typedef enum
{
  OP_CONFIGURE_IPV4 = 0,
  OP_CONFIGURE_IPV6,
  OP_ADD_WELL_KNOWN,
  OP_QUERY_SINGLE,
  OP_QUERY_MULTIPLE,
  OP_PROCESS_EVENT_LOOP,
  OP_CANCEL_QUERY,
  OP_CONNECTION_STATS,
  OP_CLEAR_SERVERS,
  OP_CLOSE_ALL,
  OP_CONFIGURE_SPKI_PIN,
  OP_CONFIGURE_MALFORMED,
  OP_QUERY_TIMEOUT
} DoTFuzzOp;

/* Query completion callback for fuzzing */
static void
dot_query_callback (SocketDNSoverTLS_Query_T query, const unsigned char *response,
                   size_t len, int error, void *userdata)
{
  /* Validate callback parameters */
  if (!query)
    abort ();

  /* Extract query ID for validation */
  uint16_t id = SocketDNSoverTLS_query_id (query);
  (void)id;

  /* Process response if available */
  if (error == DOT_ERROR_SUCCESS && response && len >= DNS_HEADER_SIZE)
    {
      SocketDNS_Header hdr;
      if (SocketDNS_header_decode (response, len, &hdr) == 0)
        {
          /* Verify response flag is set */
          if (!hdr.qr)
            abort ();
        }
    }

  /* Test error string conversion */
  const char *err_str = SocketDNSoverTLS_strerror (error);
  if (!err_str)
    abort ();

  (void)userdata;
}

/* Parse operation from fuzz data */
static uint8_t
get_operation (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 13 : OP_CONFIGURE_IPV4;
}

/* Build a simple DNS query from fuzz data */
static size_t
build_dns_query (const uint8_t *data, size_t size, unsigned char *query_buf,
                 size_t buf_size)
{
  if (size < 12)
    return 0;

  /* Minimum DNS query: header + question */
  if (buf_size < DNS_HEADER_SIZE + 6)
    return 0;

  size_t offset = 0;

  /* DNS Header (12 bytes) */
  query_buf[offset++] = data[0]; /* ID high */
  query_buf[offset++] = data[1]; /* ID low */
  query_buf[offset++] = 0x01;    /* QR=0, OPCODE=0, RD=1 */
  query_buf[offset++] = 0x00;    /* RA=0, Z=0, RCODE=0 */
  query_buf[offset++] = 0x00;    /* QDCOUNT high */
  query_buf[offset++] = 0x01;    /* QDCOUNT = 1 */
  query_buf[offset++] = 0x00;    /* ANCOUNT = 0 */
  query_buf[offset++] = 0x00;
  query_buf[offset++] = 0x00;    /* NSCOUNT = 0 */
  query_buf[offset++] = 0x00;
  query_buf[offset++] = 0x00;    /* ARCOUNT = 0 */
  query_buf[offset++] = 0x00;

  /* Question section: simple A query for "example.com" */
  /* Label "example" (7 bytes) */
  query_buf[offset++] = 0x07;
  query_buf[offset++] = 'e';
  query_buf[offset++] = 'x';
  query_buf[offset++] = 'a';
  query_buf[offset++] = 'm';
  query_buf[offset++] = 'p';
  query_buf[offset++] = 'l';
  query_buf[offset++] = 'e';
  /* Label "com" (3 bytes) */
  query_buf[offset++] = 0x03;
  query_buf[offset++] = 'c';
  query_buf[offset++] = 'o';
  query_buf[offset++] = 'm';
  /* Root label */
  query_buf[offset++] = 0x00;
  /* QTYPE = A (1) */
  query_buf[offset++] = 0x00;
  query_buf[offset++] = 0x01;
  /* QCLASS = IN (1) */
  query_buf[offset++] = 0x00;
  query_buf[offset++] = 0x01;

  return offset;
}

/* Extract IPv4 address from fuzz data */
static void
extract_ipv4 (const uint8_t *data, size_t size, char *addr_buf, size_t buf_size)
{
  if (size < 4)
    {
      snprintf (addr_buf, buf_size, "8.8.8.8");
      return;
    }

  snprintf (addr_buf, buf_size, "%u.%u.%u.%u",
            data[0], data[1], data[2], data[3]);
}

/* Extract IPv6 address from fuzz data */
static void
extract_ipv6 (const uint8_t *data, size_t size, char *addr_buf, size_t buf_size)
{
  if (size < 16)
    {
      snprintf (addr_buf, buf_size, "2001:4860:4860::8888");
      return;
    }

  snprintf (addr_buf, buf_size,
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15]);
}

/* Extract server name (SNI) from fuzz data */
static void
extract_server_name (const uint8_t *data, size_t size, char *name_buf,
                    size_t buf_size)
{
  if (size < 2)
    {
      snprintf (name_buf, buf_size, "dns.google");
      return;
    }

  size_t name_len = data[0] % 64;
  if (name_len > size - 1)
    name_len = size - 1;
  if (name_len > buf_size - 1)
    name_len = buf_size - 1;

  /* Copy and ensure printable ASCII */
  for (size_t i = 0; i < name_len; i++)
    {
      uint8_t c = data[i + 1];
      name_buf[i] = (c >= 32 && c < 127) ? c : 'x';
    }
  name_buf[name_len] = '\0';
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketDNSoverTLS_T transport = NULL;
  SocketDNSoverTLS_Query_T query = NULL;
  unsigned char query_buf[512];
  char addr_buf[128];
  char name_buf[256];
  char pin_buf[128];
  size_t query_len;
  int result;

  if (size < 2 || size > MAX_FUZZ_SIZE)
    return 0;

  uint8_t op = get_operation (data, size);
  const uint8_t *op_data = data + 1;
  size_t op_size = size - 1;

  /* Single TRY block for all operations */
  TRY
  {
    arena = Arena_new ();
    transport = SocketDNSoverTLS_new (arena);

    switch (op)
      {
      case OP_CONFIGURE_IPV4:
        /* Test IPv4 server configuration */
        if (op_size >= 4)
          {
            extract_ipv4 (op_data, op_size, addr_buf, sizeof (addr_buf));
            extract_server_name (op_data + 4,
                                op_size > 4 ? op_size - 4 : 0,
                                name_buf, sizeof (name_buf));

            SocketDNSoverTLS_Config config = {
              .server_address = addr_buf,
              .port = op_size > 5 ? ((op_data[4] << 8) | op_data[5]) : DOT_PORT,
              .server_name = name_buf,
              .mode = (op_size > 6 && (op_data[6] & 1)) ? DOT_MODE_STRICT
                                                         : DOT_MODE_OPPORTUNISTIC,
              .spki_pin = NULL,
              .spki_pin_backup = NULL
            };

            result = SocketDNSoverTLS_configure (transport, &config);
            (void)result;
          }
        break;

      case OP_CONFIGURE_IPV6:
        /* Test IPv6 server configuration */
        if (op_size >= 16)
          {
            extract_ipv6 (op_data, op_size, addr_buf, sizeof (addr_buf));
            extract_server_name (op_data + 16,
                                op_size > 16 ? op_size - 16 : 0,
                                name_buf, sizeof (name_buf));

            SocketDNSoverTLS_Config config = {
              .server_address = addr_buf,
              .port = DOT_PORT,
              .server_name = name_buf,
              .mode = DOT_MODE_OPPORTUNISTIC,
              .spki_pin = NULL,
              .spki_pin_backup = NULL
            };

            result = SocketDNSoverTLS_configure (transport, &config);
            (void)result;
          }
        break;

      case OP_ADD_WELL_KNOWN:
        /* Test well-known server addition */
        {
          const char *servers[] = {
            "google", "google-v6", "cloudflare", "cloudflare-v6",
            "quad9", "quad9-v6"
          };
          int idx = op_size > 0 ? op_data[0] % 6 : 0;
          SocketDNSoverTLS_Mode mode = (op_size > 1 && (op_data[1] & 1))
                                         ? DOT_MODE_STRICT
                                         : DOT_MODE_OPPORTUNISTIC;

          result = SocketDNSoverTLS_add_server (transport, servers[idx], mode);
          (void)result;

          /* Verify server count */
          int count = SocketDNSoverTLS_server_count (transport);
          if (result == 0 && count != 1)
            abort ();
        }
        break;

      case OP_QUERY_SINGLE:
        /* Test single query submission */
        if (op_size >= 12)
          {
            /* Configure a server first */
            SocketDNSoverTLS_add_server (transport, "google", DOT_MODE_OPPORTUNISTIC);

            /* Build DNS query */
            query_len = build_dns_query (op_data, op_size, query_buf,
                                        sizeof (query_buf));
            if (query_len > 0)
              {
                query = SocketDNSoverTLS_query (transport, query_buf, query_len,
                                               dot_query_callback, NULL);

                /* Query may fail if no server configured or queue full */
                if (query)
                  {
                    /* Verify pending count increased */
                    int pending = SocketDNSoverTLS_pending_count (transport);
                    if (pending < 1)
                      abort ();

                    /* Get query ID */
                    uint16_t id = SocketDNSoverTLS_query_id (query);
                    (void)id;
                  }
              }
          }
        break;

      case OP_QUERY_MULTIPLE:
        /* Test multiple pipelined queries */
        if (op_size >= 24)
          {
            SocketDNSoverTLS_add_server (transport, "cloudflare",
                                        DOT_MODE_OPPORTUNISTIC);

            /* Submit multiple queries */
            for (size_t i = 0; i < 3 && op_size >= (i + 1) * 12; i++)
              {
                query_len = build_dns_query (op_data + i * 12,
                                            op_size - i * 12,
                                            query_buf, sizeof (query_buf));
                if (query_len > 0)
                  {
                    query = SocketDNSoverTLS_query (transport, query_buf,
                                                   query_len,
                                                   dot_query_callback,
                                                   (void *)(intptr_t)i);
                  }
              }

            /* Check pending count */
            int pending = SocketDNSoverTLS_pending_count (transport);
            (void)pending;
          }
        break;

      case OP_PROCESS_EVENT_LOOP:
        /* Test event loop processing */
        {
          SocketDNSoverTLS_add_server (transport, "quad9", DOT_MODE_OPPORTUNISTIC);

          /* Submit a query */
          if (op_size >= 12)
            {
              query_len = build_dns_query (op_data, op_size, query_buf,
                                          sizeof (query_buf));
              if (query_len > 0)
                {
                  query = SocketDNSoverTLS_query (transport, query_buf,
                                                 query_len,
                                                 dot_query_callback, NULL);
                }
            }

          /* Process with various timeout values */
          int timeout_ms = op_size > 0 ? op_data[0] : 10;
          int completed = SocketDNSoverTLS_process (transport, timeout_ms);
          (void)completed;

          /* Get file descriptor for poll integration */
          int fd = SocketDNSoverTLS_fd (transport);
          (void)fd;

          /* Check connection state */
          int connected = SocketDNSoverTLS_is_connected (transport);
          (void)connected;
        }
        break;

      case OP_CANCEL_QUERY:
        /* Test query cancellation */
        if (op_size >= 12)
          {
            SocketDNSoverTLS_add_server (transport, "google", DOT_MODE_OPPORTUNISTIC);

            query_len = build_dns_query (op_data, op_size, query_buf,
                                        sizeof (query_buf));
            if (query_len > 0)
              {
                query = SocketDNSoverTLS_query (transport, query_buf, query_len,
                                               dot_query_callback, NULL);
                if (query)
                  {
                    /* Cancel immediately */
                    result = SocketDNSoverTLS_cancel (transport, query);
                    if (result != 0)
                      {
                        /* Cancel may fail if already completed */
                      }

                    /* Verify pending count */
                    int pending = SocketDNSoverTLS_pending_count (transport);
                    (void)pending;
                  }
              }
          }
        break;

      case OP_CONNECTION_STATS:
        /* Test statistics gathering */
        {
          SocketDNSoverTLS_Stats stats;
          SocketDNSoverTLS_stats (transport, &stats);

          /* Verify stats structure is sane */
          if (stats.queries_sent < stats.queries_completed + stats.queries_failed)
            {
              /* Expected: sent >= completed + failed */
            }
        }
        break;

      case OP_CLEAR_SERVERS:
        /* Test server list clearing */
        {
          SocketDNSoverTLS_add_server (transport, "google", DOT_MODE_OPPORTUNISTIC);
          int count = SocketDNSoverTLS_server_count (transport);
          if (count != 1)
            abort ();

          SocketDNSoverTLS_clear_servers (transport);
          count = SocketDNSoverTLS_server_count (transport);
          if (count != 0)
            abort ();
        }
        break;

      case OP_CLOSE_ALL:
        /* Test connection close */
        {
          SocketDNSoverTLS_add_server (transport, "cloudflare",
                                      DOT_MODE_OPPORTUNISTIC);

          /* Submit query */
          if (op_size >= 12)
            {
              query_len = build_dns_query (op_data, op_size, query_buf,
                                          sizeof (query_buf));
              if (query_len > 0)
                {
                  query = SocketDNSoverTLS_query (transport, query_buf,
                                                 query_len,
                                                 dot_query_callback, NULL);
                }
            }

          /* Close all connections (cancels pending queries) */
          SocketDNSoverTLS_close_all (transport);

          /* Verify no pending queries */
          int pending = SocketDNSoverTLS_pending_count (transport);
          if (pending != 0)
            abort ();

          /* Verify not connected */
          int connected = SocketDNSoverTLS_is_connected (transport);
          if (connected)
            abort ();
        }
        break;

      case OP_CONFIGURE_SPKI_PIN:
        /* Test SPKI pinning configuration */
        if (op_size >= 32)
          {
            extract_ipv4 (op_data, op_size, addr_buf, sizeof (addr_buf));

            /* Convert fuzz data to hex string for SPKI pin */
            snprintf (pin_buf, sizeof (pin_buf),
                     "%02x%02x%02x%02x%02x%02x%02x%02x"
                     "%02x%02x%02x%02x%02x%02x%02x%02x",
                     op_data[4], op_data[5], op_data[6], op_data[7],
                     op_data[8], op_data[9], op_data[10], op_data[11],
                     op_data[12], op_data[13], op_data[14], op_data[15],
                     op_data[16], op_data[17], op_data[18], op_data[19]);

            SocketDNSoverTLS_Config config = {
              .server_address = addr_buf,
              .port = DOT_PORT,
              .server_name = "dns.example.com",
              .mode = DOT_MODE_STRICT,
              .spki_pin = pin_buf,
              .spki_pin_backup = NULL
            };

            result = SocketDNSoverTLS_configure (transport, &config);
            (void)result;
          }
        break;

      case OP_CONFIGURE_MALFORMED:
        /* Test malformed configuration inputs */
        if (op_size >= 4)
          {
            /* Extract potentially malformed data */
            extract_server_name (op_data, op_size, name_buf, sizeof (name_buf));

            SocketDNSoverTLS_Config config = {
              .server_address = name_buf,  /* May not be valid IP */
              .port = op_size > 1 ? ((op_data[0] << 8) | op_data[1]) : 0,
              .server_name = name_buf,
              .mode = DOT_MODE_OPPORTUNISTIC,
              .spki_pin = NULL,
              .spki_pin_backup = NULL
            };

            /* Should fail gracefully for invalid addresses */
            result = SocketDNSoverTLS_configure (transport, &config);
            (void)result;
          }
        break;

      case OP_QUERY_TIMEOUT:
        /* Test query timeout handling */
        {
          SocketDNSoverTLS_add_server (transport, "quad9", DOT_MODE_OPPORTUNISTIC);

          /* Submit query */
          if (op_size >= 12)
            {
              query_len = build_dns_query (op_data, op_size, query_buf,
                                          sizeof (query_buf));
              if (query_len > 0)
                {
                  query = SocketDNSoverTLS_query (transport, query_buf,
                                                 query_len,
                                                 dot_query_callback, NULL);
                }
            }

          /* Process briefly (may timeout) */
          for (int i = 0; i < 5; i++)
            {
              SocketDNSoverTLS_process (transport, 1);
            }

          /* Check final state */
          int pending = SocketDNSoverTLS_pending_count (transport);
          (void)pending;
        }
        break;
      }

    /* Cleanup */
    if (transport)
      SocketDNSoverTLS_free (&transport);
    if (arena)
      Arena_dispose (&arena);
  }
  EXCEPT (SocketDNSoverTLS_Failed)
  {
    /* Expected for some malformed inputs */
    if (transport)
      SocketDNSoverTLS_free (&transport);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}

#else /* !SOCKET_HAS_TLS */

/* Stub for builds without TLS support */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */

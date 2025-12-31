/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_alpn.c - Fuzzer for ALPN Protocol Negotiation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Wire format parsing (length-prefixed strings per RFC 7301)
 * - Protocol count validation (SOCKET_TLS_MAX_ALPN_PROTOCOLS = 16)
 * - Protocol length validation (1-255 bytes, printable ASCII 0x21-0x7E)
 * - Overflow protection in wire format building
 * - Custom ALPN callback validation
 * - ALPN temp buffer cleanup (UAF prevention)
 * - Edge cases: empty strings, control chars, max lengths
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_tls_alpn
 * Run:   ./fuzz_tls_alpn corpus/tls_alpn/ -fork=16 -max_len=4096
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLSContext.h"

/* Maximum protocols to test */
#define MAX_TEST_PROTOS 32

/* Known valid ALPN protocol names for baseline testing */
static const char *VALID_ALPN_PROTOS[]
    = { "h2",          /* HTTP/2 */
        "http/1.1",    /* HTTP/1.1 */
        "spdy/3.1",    /* SPDY 3.1 (legacy) */
        "h2c",         /* HTTP/2 cleartext */
        "grpc",        /* gRPC */
        "webrtc",      /* WebRTC */
        "c-webrtc",    /* Confidential WebRTC */
        "ftp",         /* FTP */
        "imap",        /* IMAP */
        "pop3",        /* POP3 */
        "managesieve", /* Manage Sieve */
        "coap",        /* CoAP */
        "mqtt",        /* MQTT */
        "acme-tls/1",  /* ACME TLS-ALPN challenge */
        "dot",         /* DNS over TLS */
        NULL };

/* Edge case protocol names for testing */
static const char *EDGE_CASE_PROTOS[]
    = { "a",                             /* Single char (minimum valid) */
        "AB",                            /* Uppercase */
        "a-b",                           /* Hyphen */
        "proto123",                      /* Alphanumeric */
        "x!\"#$%&'()*+,-./:;<=>?@[\\]^", /* Special printable chars */
        NULL };

/* Callback state for testing */
static volatile int callback_invoked = 0;
static volatile const char *callback_selection = NULL;

/**
 * test_alpn_callback - Custom ALPN selection callback for testing
 * @client_protos: Client-offered protocols
 * @client_count: Number of client protocols
 * @user_data: User data (ignored)
 *
 * Returns: First client protocol or NULL
 */
static const char *
test_alpn_callback (const char **client_protos,
                    size_t client_count,
                    void *user_data)
{
  (void)user_data;
  callback_invoked = 1;

  if (client_count > 0 && client_protos && client_protos[0])
    {
      callback_selection = client_protos[0];
      return client_protos[0];
    }
  return NULL;
}

/**
 * parse_protocols_from_fuzz - Extract protocol strings from fuzz data
 * @data: Fuzz input
 * @size: Size of fuzz input
 * @protos_out: Output array of protocol strings (caller frees)
 * @count_out: Output protocol count
 *
 * Input format: Each protocol is null-terminated in the fuzz data.
 * Returns array of pointers into data (no allocation needed for strings).
 */
static void
parse_protocols_from_fuzz (const uint8_t *data,
                           size_t size,
                           const char ***protos_out,
                           size_t *count_out)
{
  *protos_out = NULL;
  *count_out = 0;

  if (size < 2)
    return;

  /* Count null-terminated strings */
  size_t count = 0;
  for (size_t i = 0; i < size && count < MAX_TEST_PROTOS; i++)
    {
      if (data[i] == '\0')
        count++;
    }

  if (count == 0)
    return;

  /* Allocate pointer array */
  const char **protos = calloc (count, sizeof (const char *));
  if (!protos)
    return;

  /* Build pointer array */
  size_t idx = 0;
  const char *start = (const char *)data;
  for (size_t i = 0; i < size && idx < count; i++)
    {
      if (data[i] == '\0')
        {
          /* Only add non-empty strings */
          if (start < (const char *)&data[i])
            {
              protos[idx++] = start;
            }
          start = (const char *)&data[i + 1];
        }
    }

  if (idx == 0)
    {
      free (protos);
      return;
    }

  *protos_out = protos;
  *count_out = idx;
}

/**
 * test_valid_protocols - Test with known valid protocol names
 * @ctx: TLS context
 * @data: Fuzz data for selection
 * @size: Size of fuzz data
 */
static void
test_valid_protocols (SocketTLSContext_T ctx, const uint8_t *data, size_t size)
{
  size_t num_protos;
  size_t i;

  if (size < 1)
    return;

  /* Count valid protocols */
  for (num_protos = 0; VALID_ALPN_PROTOS[num_protos] != NULL; num_protos++)
    ;

  /* Select subset based on fuzz data */
  size_t start_idx = data[0] % num_protos;
  size_t count = (size > 1 ? data[1] % 5 : 1) + 1; /* 1-5 protocols */

  if (count > num_protos)
    count = num_protos;

  const char **subset = calloc (count, sizeof (const char *));
  if (!subset)
    return;

  for (i = 0; i < count; i++)
    subset[i] = VALID_ALPN_PROTOS[(start_idx + i) % num_protos];

  TRY
  {
    SocketTLSContext_set_alpn_protos (ctx, subset, count);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Should not happen with valid protocols */
  }
  END_TRY;

  free (subset);
}

/**
 * test_edge_cases - Test edge case protocol names
 * @ctx: TLS context
 */
static void
test_edge_cases (SocketTLSContext_T ctx)
{
  size_t count;
  size_t i;

  /* Count edge case protocols */
  for (count = 0; EDGE_CASE_PROTOS[count] != NULL; count++)
    ;

  /* Test each individually */
  for (i = 0; i < count; i++)
    {
      const char *proto[1] = { EDGE_CASE_PROTOS[i] };
      TRY
      {
        SocketTLSContext_set_alpn_protos (ctx, proto, 1);
      }
      EXCEPT (SocketTLS_Failed)
      {
        /* Some edge cases may be rejected */
      }
      END_TRY;
    }
}

/**
 * test_callback_registration - Test ALPN callback registration
 * @ctx: TLS context
 */
static void
test_callback_registration (SocketTLSContext_T ctx)
{
  callback_invoked = 0;
  callback_selection = NULL;

  /* Register callback */
  SocketTLSContext_set_alpn_callback (ctx, test_alpn_callback, NULL);

  /* Set some protocols to trigger callback setup */
  const char *protos[] = { "h2", "http/1.1" };
  TRY
  {
    SocketTLSContext_set_alpn_protos (ctx, protos, 2);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Ignore */
  }
  END_TRY;

  /* Clear callback */
  SocketTLSContext_set_alpn_callback (ctx, NULL, NULL);
}

/**
 * test_max_protocols - Test with maximum protocol count (16)
 * @ctx: TLS context
 */
static void
test_max_protocols (SocketTLSContext_T ctx)
{
  const char *protos[16]
      = { "proto1",  "proto2",  "proto3",  "proto4",  "proto5",  "proto6",
          "proto7",  "proto8",  "proto9",  "proto10", "proto11", "proto12",
          "proto13", "proto14", "proto15", "proto16" };

  TRY
  {
    SocketTLSContext_set_alpn_protos (ctx, protos, 16);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* May fail if exceeds configured maximum */
  }
  END_TRY;
}

/**
 * test_protocol_with_invalid_chars - Test protocols with control/invalid chars
 * @ctx: TLS context
 * @data: Fuzz data
 * @size: Size of fuzz data
 */
static void
test_protocol_with_invalid_chars (SocketTLSContext_T ctx,
                                  const uint8_t *data,
                                  size_t size)
{
  char buffer[64];
  size_t copy_len;

  if (size < 3)
    return;

  /* Create a protocol name with potentially invalid characters */
  copy_len = (size - 1 > sizeof (buffer) - 1) ? sizeof (buffer) - 1 : size - 1;
  memcpy (buffer, data + 1, copy_len);
  buffer[copy_len] = '\0';

  const char *proto[1] = { buffer };
  TRY
  {
    SocketTLSContext_set_alpn_protos (ctx, proto, 1);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid chars (control chars, spaces, etc.) */
  }
  END_TRY;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: Protocol strings (null-terminated) or raw data
 *
 * Tests ALPN protocol list handling without actual TLS connections.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketTLSContext_T volatile ctx = NULL;
  const char *volatile *volatile protos = NULL;
  volatile size_t count = 0;

  if (size < 3)
    return 0;

  uint8_t op = data[0];
  const uint8_t *proto_data = data + 1;
  size_t proto_size = size - 1;

  TRY
  {
    /* Create a minimal client context for testing */
    ctx = SocketTLSContext_new_client (NULL);

    /* Parse protocols from fuzz data */
    parse_protocols_from_fuzz (
        proto_data, proto_size, (const char ***)&protos, (size_t *)&count);

    if (ctx)
      {
        switch (op % 8)
          {
          case 0:
            /* Test set_alpn_protos with fuzzed protocol list */
            if (protos && count > 0)
              SocketTLSContext_set_alpn_protos (
                  (SocketTLSContext_T)ctx, (const char **)protos, count);
            break;

          case 1:
            /* Test with single protocol */
            if (protos && count >= 1)
              {
                const char *single[1] = { (const char *)protos[0] };
                SocketTLSContext_set_alpn_protos (
                    (SocketTLSContext_T)ctx, single, 1);
              }
            break;

          case 2:
            /* Test with subset of protocols */
            if (protos && count > 0)
              {
                size_t subset = (count > 2) ? count / 2 : count;
                SocketTLSContext_set_alpn_protos (
                    (SocketTLSContext_T)ctx, (const char **)protos, subset);
              }
            break;

          case 3:
            /* Test with known valid protocols */
            test_valid_protocols (
                (SocketTLSContext_T)ctx, proto_data, proto_size);
            break;

          case 4:
            /* Test edge case protocol names */
            test_edge_cases ((SocketTLSContext_T)ctx);
            break;

          case 5:
            /* Test ALPN callback registration */
            test_callback_registration ((SocketTLSContext_T)ctx);
            break;

          case 6:
            /* Test maximum protocol count */
            test_max_protocols ((SocketTLSContext_T)ctx);
            break;

          case 7:
            /* Test with potentially invalid characters */
            test_protocol_with_invalid_chars (
                (SocketTLSContext_T)ctx, proto_data, proto_size);
            break;
          }
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid protocols */
  }
  FINALLY
  {
    if (protos)
      free ((void *)protos);
    if (ctx)
      {
        SocketTLSContext_T tmp = (SocketTLSContext_T)ctx;
        SocketTLSContext_free (&tmp);
        ctx = NULL;
      }
  }
  END_TRY;

  return 0;
}

#else /* !SOCKET_HAS_TLS */

/* Stub for non-TLS builds */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */

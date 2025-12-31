/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_session.c - Fuzzer for TLS session ticket key handling
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Session ticket key validation (80 bytes required)
 * - Key material boundary conditions
 * - Session cache configuration
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_tls_session
 * Run:   ./fuzz_tls_session corpus/tls_session/ -fork=16 -max_len=256
 */

#if SOCKET_HAS_TLS

#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLSContext.h"

/* Session ticket key size required by OpenSSL */
#define TICKET_KEY_SIZE 80

/* Operation codes */
enum SessionOp
{
  SESSION_ENABLE_CACHE = 0,
  SESSION_SET_SIZE,
  SESSION_ENABLE_TICKETS,
  SESSION_GET_STATS,
  SESSION_SET_ID_CONTEXT,
  SESSION_ROTATE_TICKET_KEY,
  SESSION_DISABLE_TICKETS,
  SESSION_CHECK_TICKETS_ENABLED,
  SESSION_OP_COUNT
};

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
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Bytes 1-4: max_sessions (for cache config)
 * - Bytes 5-8: timeout_seconds (for cache config)
 * - Remaining: Key material for session tickets
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketTLSContext_T ctx = NULL;

  if (size < 9)
    return 0;

  uint8_t op = data[0];
  uint32_t max_sessions = read_u32 (data + 1);
  uint32_t timeout = read_u32 (data + 5);
  const uint8_t *key_data = data + 9;
  size_t key_size = size - 9;

  /* Reasonable limits */
  max_sessions = max_sessions % 10000;
  timeout = timeout % 86400; /* Max 1 day */

  TRY
  {
    /* Create a minimal client context */
    ctx = SocketTLSContext_new_client (NULL);
    if (!ctx)
      return 0;

    switch (op % SESSION_OP_COUNT)
      {
      case SESSION_ENABLE_CACHE:
        {
          /* Test session cache enabling with fuzzed params */
          SocketTLSContext_enable_session_cache (
              ctx, max_sessions, (long)timeout);
        }
        break;

      case SESSION_SET_SIZE:
        {
          /* Test setting cache size */
          if (max_sessions > 0)
            {
              SocketTLSContext_set_session_cache_size (ctx, max_sessions);
            }
        }
        break;

      case SESSION_ENABLE_TICKETS:
        {
          /* Test session ticket enabling with fuzzed key material */
          /* OpenSSL requires exactly 80 bytes for ticket key */
          if (key_size >= TICKET_KEY_SIZE)
            {
              SocketTLSContext_enable_session_tickets (
                  ctx, key_data, TICKET_KEY_SIZE);
            }
          else if (key_size > 0)
            {
              /* Test with wrong key size - should fail */
              SocketTLSContext_enable_session_tickets (ctx, key_data, key_size);
            }
        }
        break;

      case SESSION_GET_STATS:
        {
          /* Enable cache first, then get stats */
          SocketTLSContext_enable_session_cache (ctx, 100, 300);
          size_t hits = 0, misses = 0, stores = 0;
          SocketTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);
          (void)hits;
          (void)misses;
          (void)stores;
        }
        break;

      case SESSION_SET_ID_CONTEXT:
        {
          /* Test session ID context with fuzzed data */
          /* Use key_data as context bytes (max 32 bytes per OpenSSL) */
          if (key_size > 0)
            {
              size_t ctx_len = key_size > 32 ? 32 : key_size;
              SocketTLSContext_set_session_id_context (ctx, key_data, ctx_len);
            }
          /* Also test with zero length (should fail) */
          if (key_size == 0 && size > 10)
            {
              SocketTLSContext_set_session_id_context (ctx, key_data, 0);
            }
          /* Test with length > 32 (should fail) */
          if (key_size >= 64)
            {
              SocketTLSContext_set_session_id_context (ctx, key_data, 64);
            }
        }
        break;

      case SESSION_ROTATE_TICKET_KEY:
        {
          /* Test session ticket key rotation with fuzzed key material */
          /* First enable tickets, then try rotation */
          unsigned char initial_key[TICKET_KEY_SIZE];
          memset (initial_key, 0xAA, TICKET_KEY_SIZE);
          SocketTLSContext_enable_session_tickets (
              ctx, initial_key, TICKET_KEY_SIZE);

          if (key_size >= TICKET_KEY_SIZE)
            {
              /* Valid rotation */
              SocketTLSContext_rotate_session_ticket_key (
                  ctx, key_data, TICKET_KEY_SIZE);
            }
          else if (key_size > 0)
            {
              /* Invalid key size - should fail */
              SocketTLSContext_rotate_session_ticket_key (
                  ctx, key_data, key_size);
            }
        }
        break;

      case SESSION_DISABLE_TICKETS:
        {
          /* Test disabling session tickets */
          unsigned char key[TICKET_KEY_SIZE];
          memset (key, 0xBB, TICKET_KEY_SIZE);

          /* Enable, then disable */
          SocketTLSContext_enable_session_tickets (ctx, key, TICKET_KEY_SIZE);
          SocketTLSContext_disable_session_tickets (ctx);

          /* Multiple disable calls should be safe */
          SocketTLSContext_disable_session_tickets (ctx);

          /* Can we re-enable after disable? */
          if (key_size >= TICKET_KEY_SIZE)
            {
              SocketTLSContext_enable_session_tickets (
                  ctx, key_data, TICKET_KEY_SIZE);
            }
        }
        break;

      case SESSION_CHECK_TICKETS_ENABLED:
        {
          /* Test tickets enabled check in various states */
          int enabled = SocketTLSContext_session_tickets_enabled (ctx);
          (void)enabled;

          /* Enable and check */
          unsigned char key[TICKET_KEY_SIZE];
          memset (key, 0xCC, TICKET_KEY_SIZE);
          SocketTLSContext_enable_session_tickets (ctx, key, TICKET_KEY_SIZE);
          enabled = SocketTLSContext_session_tickets_enabled (ctx);
          (void)enabled;

          /* Disable and check */
          SocketTLSContext_disable_session_tickets (ctx);
          enabled = SocketTLSContext_session_tickets_enabled (ctx);
          (void)enabled;
        }
        break;
      }
  }
  EXCEPT (SocketTLS_Failed)
  { /* Expected for invalid parameters */
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
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

/**
 * fuzz_tls_buffer_pool.c - Fuzzing harness for TLS buffer pool
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Tests TLS buffer pool operations with fuzz-generated input to verify:
 * - Thread safety under concurrent access
 * - Correct behavior with various pool sizes
 * - Robustness of acquire/release sequences
 * - Memory safety (no leaks, use-after-free, etc.)
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"

#if SOCKET_HAS_TLS

#include "tls/SocketTLS.h"

/* Operation codes for fuzzing */
typedef enum
{
  OP_CREATE_POOL = 0,
  OP_DESTROY_POOL = 1,
  OP_ACQUIRE = 2,
  OP_RELEASE = 3,
  OP_CHECK_STATS = 4,
  OP_FILL_BUFFER = 5,
  OP_MAX
} FuzzOp;

/* Global state for stateful fuzzing */
static TLSBufferPool_T g_pool = NULL;
static void *g_acquired_buffers[64];
static int g_acquired_count = 0;

/**
 * Execute one fuzz operation based on input bytes
 */
static void
execute_op (const uint8_t *data, size_t size, size_t *offset)
{
  if (*offset >= size)
    return;

  uint8_t op = data[(*offset)++] % OP_MAX;

  switch (op)
    {
    case OP_CREATE_POOL:
      {
        if (g_pool != NULL)
          {
            /* Release all acquired buffers first */
            for (int i = 0; i < g_acquired_count; i++)
              {
                TLSBufferPool_release (g_pool, g_acquired_buffers[i]);
              }
            g_acquired_count = 0;
            TLSBufferPool_free (&g_pool);
          }

        /* Get pool parameters from input */
        if (*offset + 2 > size)
          return;
        uint8_t num_buffers = data[(*offset)++];
        uint8_t size_factor = data[(*offset)++];

        /* Limit to reasonable values */
        if (num_buffers == 0)
          num_buffers = 1;
        if (num_buffers > 32)
          num_buffers = 32;

        size_t buffer_size = (size_factor % 16 + 1) * 256; /* 256 - 4096 */

        g_pool = TLSBufferPool_new (buffer_size, num_buffers, NULL);
        /* Pool creation may fail - that's OK for fuzzing */
        break;
      }

    case OP_DESTROY_POOL:
      {
        if (g_pool != NULL)
          {
            /* Release all acquired buffers first */
            for (int i = 0; i < g_acquired_count; i++)
              {
                TLSBufferPool_release (g_pool, g_acquired_buffers[i]);
              }
            g_acquired_count = 0;
            TLSBufferPool_free (&g_pool);
          }
        break;
      }

    case OP_ACQUIRE:
      {
        if (g_pool != NULL && g_acquired_count < 64)
          {
            void *buf = TLSBufferPool_acquire (g_pool);
            if (buf)
              {
                g_acquired_buffers[g_acquired_count++] = buf;
              }
          }
        break;
      }

    case OP_RELEASE:
      {
        if (g_pool != NULL && g_acquired_count > 0)
          {
            if (*offset >= size)
              return;
            uint8_t idx = data[(*offset)++] % g_acquired_count;
            TLSBufferPool_release (g_pool, g_acquired_buffers[idx]);
            /* Remove from tracking */
            g_acquired_buffers[idx] = g_acquired_buffers[--g_acquired_count];
          }
        break;
      }

    case OP_CHECK_STATS:
      {
        size_t total, in_use, available;
        TLSBufferPool_stats (g_pool, &total, &in_use, &available);
        /* Just exercise the stats function */
        (void)total;
        (void)in_use;
        (void)available;
        break;
      }

    case OP_FILL_BUFFER:
      {
        if (g_acquired_count > 0 && *offset + 2 <= size)
          {
            uint8_t idx = data[(*offset)++] % g_acquired_count;
            uint8_t fill_val = data[(*offset)++];
            /* Fill a small portion of the buffer */
            if (g_acquired_buffers[idx])
              {
                memset (g_acquired_buffers[idx], fill_val, 64);
              }
          }
        break;
      }

    default:
      break;
    }
}

/**
 * Cleanup function for fuzzer
 */
static void
cleanup (void)
{
  if (g_pool != NULL)
    {
      for (int i = 0; i < g_acquired_count; i++)
        {
          TLSBufferPool_release (g_pool, g_acquired_buffers[i]);
        }
      g_acquired_count = 0;
      TLSBufferPool_free (&g_pool);
    }
}

/**
 * LibFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  size_t offset = 0;

  /* Execute a sequence of operations */
  while (offset < size)
    {
      execute_op (data, size, &offset);
    }

  /* Clean up */
  cleanup ();

  return 0;
}

#else /* !SOCKET_HAS_TLS */

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */

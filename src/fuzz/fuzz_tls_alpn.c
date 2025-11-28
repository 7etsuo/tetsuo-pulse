/**
 * fuzz_tls_alpn.c - Fuzzer for ALPN wire format parsing
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Wire format parsing (length-prefixed strings)
 * - Protocol count validation
 * - Protocol length validation (0 < len <= 255)
 * - Overflow in wire format building
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_tls_alpn
 * Run:   ./fuzz_tls_alpn corpus/tls_alpn/ -fork=16 -max_len=4096
 */

#ifdef SOCKET_HAS_TLS

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
parse_protocols_from_fuzz (const uint8_t *data, size_t size,
                           const char ***protos_out, size_t *count_out)
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
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: Protocol strings (null-terminated)
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
    parse_protocols_from_fuzz (proto_data, proto_size, 
                               (const char ***)&protos, (size_t *)&count);

    if (ctx && protos && count > 0)
      {
        switch (op % 3)
          {
          case 0:
            /* Test set_alpn_protos with fuzzed protocol list */
            SocketTLSContext_set_alpn_protos ((SocketTLSContext_T)ctx, 
                                              (const char **)protos, count);
            break;

          case 1:
            /* Test with single protocol */
            if (count >= 1)
              {
                const char *single[1] = { (const char *)protos[0] };
                SocketTLSContext_set_alpn_protos ((SocketTLSContext_T)ctx, 
                                                  single, 1);
              }
            break;

          case 2:
            /* Test with subset of protocols */
            {
              size_t subset = (count > 2) ? count / 2 : count;
              SocketTLSContext_set_alpn_protos ((SocketTLSContext_T)ctx,
                                                (const char **)protos, subset);
            }
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


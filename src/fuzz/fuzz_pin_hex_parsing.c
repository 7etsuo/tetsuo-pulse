/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_pin_hex_parsing.c - Fuzzer for Certificate Pin Hex Parsing
 *
 * Part of the Socket Library Fuzzing Suite (Section 8.3)
 *
 * Targets:
 * - Hex-encoded pin parsing
 * - Pin prefix handling (sha256//)
 * - Binary pin handling
 * - Pin validation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_pin_hex_parsing
 * Run:   ./fuzz_pin_hex_parsing corpus/pins/ -fork=16 -max_len=256
 */

#if SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "tls/SocketTLSContext.h"

/* Ignore SIGPIPE */
__attribute__ ((constructor)) static void
ignore_sigpipe (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types */
typedef enum
{
  OP_ADD_HEX_PIN = 0,
  OP_ADD_BINARY_PIN,
  OP_ADD_HEX_WITH_PREFIX,
  OP_VERIFY_PIN,
  OP_MULTIPLE_PINS,
  OP_CLEAR_PINS,
  OP_PIN_COUNT,
  OP_HEX_VARIATIONS,
  OP_COUNT
} PinOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % OP_COUNT : 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  const uint8_t *pin_data = data + 1;
  size_t pin_size = size - 1;

  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    if (!ctx)
      return 0;

    switch (op)
      {
      case OP_ADD_HEX_PIN:
        {
          /* Try adding fuzz data as hex pin */
          char hex_str[256];
          size_t hex_len = pin_size > 255 ? 255 : pin_size;
          memcpy (hex_str, pin_data, hex_len);
          hex_str[hex_len] = '\0';

          TRY { SocketTLSContext_add_pin_hex (ctx, hex_str); }
          EXCEPT (SocketTLS_Failed) { /* Expected for invalid hex */ }
          END_TRY;
        }
        break;

      case OP_ADD_BINARY_PIN:
        {
          /* Try adding as binary pin (requires 32 bytes) */
          if (pin_size >= 32)
            {
              SocketTLSContext_add_pin (ctx, pin_data);
            }
          else
            {
              /* Pad with zeros */
              unsigned char padded[32] = {0};
              memcpy (padded, pin_data, pin_size);
              SocketTLSContext_add_pin (ctx, padded);
            }
        }
        break;

      case OP_ADD_HEX_WITH_PREFIX:
        {
          /* Add with sha256// prefix */
          char hex_str[256] = "sha256//";
          size_t prefix_len = strlen (hex_str);
          size_t remain = sizeof (hex_str) - prefix_len - 1;
          size_t hex_len = pin_size > remain ? remain : pin_size;
          memcpy (hex_str + prefix_len, pin_data, hex_len);
          hex_str[prefix_len + hex_len] = '\0';

          TRY { SocketTLSContext_add_pin_hex (ctx, hex_str); }
          EXCEPT (SocketTLS_Failed) {}
          END_TRY;
        }
        break;

      case OP_VERIFY_PIN:
        {
          /* Add a pin then verify various data */
          unsigned char test_pin[32];
          memset (test_pin, 0xAA, 32);
          SocketTLSContext_add_pin (ctx, test_pin);

          /* Verify with fuzz data */
          if (pin_size >= 32)
            {
              int found = SocketTLSContext_verify_pin (ctx, pin_data);
              (void)found;
            }
        }
        break;

      case OP_MULTIPLE_PINS:
        {
          /* Add multiple pins */
          size_t offset = 0;
          int count = 0;
          while (offset + 32 <= pin_size && count < 10)
            {
              SocketTLSContext_add_pin (ctx, pin_data + offset);
              offset += 32;
              count++;
            }
          /* Check count */
          int pin_count = SocketTLSContext_get_pin_count (ctx);
          (void)pin_count;
        }
        break;

      case OP_CLEAR_PINS:
        {
          /* Add pins then clear */
          unsigned char pin[32];
          memset (pin, 0xBB, 32);
          SocketTLSContext_add_pin (ctx, pin);

          SocketTLSContext_clear_pins (ctx);

          /* Should have no pins */
          int count = SocketTLSContext_get_pin_count (ctx);
          if (count != 0)
            abort ();
        }
        break;

      case OP_PIN_COUNT:
        {
          /* Test pin counting */
          int initial = SocketTLSContext_get_pin_count (ctx);
          if (initial != 0)
            abort ();

          /* Add some pins */
          for (size_t i = 0; i < 5 && i * 32 < pin_size; i++)
            {
              unsigned char pin[32];
              memset (pin, (int)i, 32);
              SocketTLSContext_add_pin (ctx, pin);
            }

          int has = SocketTLSContext_has_pins (ctx);
          (void)has;
        }
        break;

      case OP_HEX_VARIATIONS:
        {
          /* Test various hex formats */
          char variations[][80] = {
            /* Valid 64 hex chars */
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            /* Uppercase */
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            /* Mixed case */
            "0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf"
          };

          for (size_t i = 0; i < sizeof (variations) / sizeof (variations[0]);
               i++)
            {
              /* Modify with some fuzz data */
              if (pin_size > i)
                {
                  size_t idx = pin_data[i % pin_size] % 64;
                  variations[i][idx]
                      = "0123456789abcdef"[pin_data[0] % 16];
                }

              TRY { SocketTLSContext_add_pin_hex (ctx, variations[i]); }
              EXCEPT (SocketTLS_Failed) {}
              END_TRY;
            }
        }
        break;
      }
  }
  EXCEPT (SocketTLS_Failed) {}
  ELSE {}
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);

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

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_cert_pinning.c - Fuzzer for Certificate Pinning
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Hex string parsing (malformed input, various lengths)
 * - Binary hash handling (truncated/oversized)
 * - Pin lookup with random hashes
 * - SPKI extraction from DER-encoded certificates
 * - Pin array operations (add, find, clear)
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_cert_pinning Run:   ./fuzz_cert_pinning corpus/pinning/ -fork=16
 * -max_len=4096
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

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* Operation codes */
enum PinningOp
{
  PIN_OP_ADD_BINARY = 0,
  PIN_OP_ADD_HEX,
  PIN_OP_ADD_HEX_PREFIX,
  PIN_OP_VERIFY_PIN,
  PIN_OP_VERIFY_CERT,
  PIN_OP_CLEAR,
  PIN_OP_MIXED_OPS,
  PIN_OP_DER_CERT,
  PIN_OP_COUNT
};

/* Thread-local exception frame for TRY/EXCEPT */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/**
 * read_u16 - Read a 16-bit value from byte stream (little-endian)
 */
static uint16_t
read_u16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * fuzz_add_binary_hash - Test adding binary hashes
 * @data: Binary data
 * @size: Data size
 *
 * Tests adding potentially malformed binary hashes.
 */
static void
fuzz_add_binary_hash (const uint8_t *data, size_t size)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  if (!ctx)
    return;

  TRY
  {
    /* Add hash regardless of size - implementation should handle */
    if (size >= 32)
      {
        SocketTLSContext_add_pin (ctx, data);
      }
    else if (size > 0)
      {
        /* Pad short data to 32 bytes */
        unsigned char padded[32] = { 0 };
        memcpy (padded, data, size);
        SocketTLSContext_add_pin (ctx, padded);
      }

    /* Verify operations don't crash */
    (void)SocketTLSContext_get_pin_count (ctx);
    (void)SocketTLSContext_has_pins (ctx);
  }
  ELSE { /* Exception expected for invalid input */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
}

/**
 * fuzz_add_hex_hash - Test adding hex-encoded hashes
 * @data: Hex string data
 * @size: Data size
 *
 * Tests adding potentially malformed hex strings.
 */
static void
fuzz_add_hex_hash (const uint8_t *data, size_t size, int with_prefix)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  if (!ctx)
    return;

  /* Create null-terminated string */
  char *hex_str = malloc (size + 1);
  if (!hex_str)
    {
      SocketTLSContext_free (&ctx);
      return;
    }
  memcpy (hex_str, data, size);
  hex_str[size] = '\0';

  /* Optionally add prefix */
  char *input = hex_str;
  char *prefixed = NULL;
  if (with_prefix && size > 0)
    {
      prefixed = malloc (size + 9); /* "sha256//" + data + null */
      if (prefixed)
        {
          memcpy (prefixed, "sha256//", 8);
          memcpy (prefixed + 8, hex_str, size + 1);
          input = prefixed;
        }
    }

  TRY
  {
    SocketTLSContext_add_pin_hex (ctx, input);
    (void)SocketTLSContext_get_pin_count (ctx);
  }
  ELSE { /* Exception expected for invalid hex */ }
  END_TRY;

  free (prefixed);
  free (hex_str);
  SocketTLSContext_free (&ctx);
}

/**
 * fuzz_verify_pin - Test pin verification
 * @data: Binary hash data
 * @size: Data size
 */
static void
fuzz_verify_pin (const uint8_t *data, size_t size)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  if (!ctx)
    return;

  TRY
  {
    /* Add some pins first */
    unsigned char pin1[32], pin2[32];
    memset (pin1, 0xAA, 32);
    memset (pin2, 0xBB, 32);
    SocketTLSContext_add_pin (ctx, pin1);
    SocketTLSContext_add_pin (ctx, pin2);

    /* Verify with fuzz data */
    if (size >= 32)
      {
        (void)SocketTLSContext_verify_pin (ctx, data);
      }
    else if (size > 0)
      {
        unsigned char padded[32] = { 0 };
        memcpy (padded, data, size);
        (void)SocketTLSContext_verify_pin (ctx, padded);
      }

    /* NULL should be safe */
    (void)SocketTLSContext_verify_pin (ctx, NULL);
  }
  ELSE { /* No exceptions expected for verify */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
}

/**
 * fuzz_verify_der_cert - Test SPKI extraction from DER certificate
 * @data: DER-encoded certificate data
 * @size: Data size
 */
static void
fuzz_verify_der_cert (const uint8_t *data, size_t size)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  if (!ctx)
    return;

  /* Try to parse as DER certificate */
  const unsigned char *p = data;
  X509 *cert = d2i_X509 (NULL, &p, (long)size);

  if (cert)
    {
      TRY
      {
        /* Add pin from cert */
        SocketTLSContext_add_pin_from_x509 (ctx, cert);

        /* Verify cert matches pin */
        (void)SocketTLSContext_verify_cert_pin (ctx, cert);
      }
      ELSE { /* Exception possible for malformed certs */ }
      END_TRY;

      X509_free (cert);
    }

  /* NULL cert should be safe */
  (void)SocketTLSContext_verify_cert_pin (ctx, NULL);

  SocketTLSContext_free (&ctx);
}

/**
 * fuzz_clear_pins - Test clearing pins
 * @data: Binary data for generating pins
 * @size: Data size
 */
static void
fuzz_clear_pins (const uint8_t *data, size_t size)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  if (!ctx)
    return;

  TRY
  {
    /* Add pins based on fuzz data */
    size_t offset = 0;
    while (offset + 32 <= size && offset / 32 < 16) /* Limit iterations */
      {
        SocketTLSContext_add_pin (ctx, data + offset);
        offset += 32;
      }

    size_t count = SocketTLSContext_get_pin_count (ctx);

    /* Clear all */
    SocketTLSContext_clear_pins (ctx);

    /* Verify cleared */
    assert (SocketTLSContext_get_pin_count (ctx) == 0);
    (void)count;

    /* Clear again should be safe */
    SocketTLSContext_clear_pins (ctx);
  }
  ELSE { /* Max pins exception possible */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
}

/**
 * fuzz_mixed_operations - Test mixed operations
 * @data: Operation sequence data
 * @size: Data size
 */
static void
fuzz_mixed_operations (const uint8_t *data, size_t size)
{
  if (size < 2)
    return;

  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  if (!ctx)
    return;

  size_t offset = 0;
  int ops = 0;

  TRY
  {
    while (offset < size && ops < 100) /* Limit iterations */
      {
        uint8_t op = data[offset++] % 6;
        ops++;

        switch (op)
          {
          case 0: /* Add binary pin */
            if (offset + 32 <= size)
              {
                SocketTLSContext_add_pin (ctx, data + offset);
                offset += 32;
              }
            break;

          case 1: /* Verify pin */
            if (offset + 32 <= size)
              {
                (void)SocketTLSContext_verify_pin (ctx, data + offset);
                offset += 32;
              }
            break;

          case 2: /* Get count */
            (void)SocketTLSContext_get_pin_count (ctx);
            break;

          case 3: /* Has pins */
            (void)SocketTLSContext_has_pins (ctx);
            break;

          case 4: /* Set enforcement */
            if (offset < size)
              {
                SocketTLSContext_set_pin_enforcement (ctx, data[offset++] % 2);
              }
            break;

          case 5: /* Clear pins */
            SocketTLSContext_clear_pins (ctx);
            break;
          }
      }
  }
  ELSE { /* Max pins exception possible */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Bytes 1-2: Size hint (little-endian, for split operations)
 * - Remaining: Operation-specific data
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 3)
    return 0;

  uint8_t op = data[0];
  uint16_t size_hint = read_u16 (data + 1);
  const uint8_t *op_data = data + 3;
  size_t op_size = size - 3;

  /* Limit size based on hint for boundary testing */
  if (size_hint > 0 && size_hint < op_size)
    op_size = size_hint;

  /* Clear stale OpenSSL errors */
  ERR_clear_error ();

  switch (op % PIN_OP_COUNT)
    {
    case PIN_OP_ADD_BINARY:
      fuzz_add_binary_hash (op_data, op_size);
      break;

    case PIN_OP_ADD_HEX:
      fuzz_add_hex_hash (op_data, op_size, 0);
      break;

    case PIN_OP_ADD_HEX_PREFIX:
      fuzz_add_hex_hash (op_data, op_size, 1);
      break;

    case PIN_OP_VERIFY_PIN:
      fuzz_verify_pin (op_data, op_size);
      break;

    case PIN_OP_VERIFY_CERT:
      fuzz_verify_der_cert (op_data, op_size);
      break;

    case PIN_OP_CLEAR:
      fuzz_clear_pins (op_data, op_size);
      break;

    case PIN_OP_MIXED_OPS:
      fuzz_mixed_operations (op_data, op_size);
      break;

    case PIN_OP_DER_CERT:
      fuzz_verify_der_cert (op_data, op_size);
      break;
    }

  /* Clear errors from parsing */
  ERR_clear_error ();

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

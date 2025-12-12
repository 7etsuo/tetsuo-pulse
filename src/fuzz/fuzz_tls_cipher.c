/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_cipher.c - Fuzzer for TLS Cipher Suite Configuration
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Cipher string parsing and validation
 * - TLS 1.2 cipher list (SSL_CTX_set_cipher_list)
 * - TLS 1.3 ciphersuites (SSL_CTX_set_ciphersuites)
 * - Edge cases: empty strings, malformed syntax, unknown ciphers
 * - Security: rejection of weak/insecure cipher configurations
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_tls_cipher
 * Run:   ./fuzz_tls_cipher corpus/tls_cipher/ -fork=16 -max_len=4096
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

/**
 * Known valid cipher strings for mutation testing.
 * These provide a baseline that should always work.
 */
static const char *VALID_CIPHER_STRINGS[] = {
    "HIGH:!aNULL:!eNULL",
    "ECDHE+AESGCM:ECDHE+CHACHA20",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "AES256-GCM-SHA384",
    "DEFAULT:!aNULL:!eNULL:!MD5",
    NULL
};

/**
 * Known valid TLS 1.3 ciphersuite strings.
 */
static const char *VALID_TLS13_SUITES[] = {
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
    NULL
};

/**
 * null_terminate_fuzz_data - Create null-terminated string from fuzz data
 * @data: Fuzz input
 * @size: Size of fuzz input
 *
 * Returns: malloc'd null-terminated string (caller frees)
 */
static char *
null_terminate_fuzz_data (const uint8_t *data, size_t size)
{
  char *str;

  if (size == 0)
    return NULL;

  str = malloc (size + 1);
  if (!str)
    return NULL;

  memcpy (str, data, size);
  str[size] = '\0';

  return str;
}

/**
 * test_cipher_validation - Test cipher validation function
 * @cipher_str: Cipher string to validate
 */
static void
test_cipher_validation (const char *cipher_str)
{
  int valid;

  if (!cipher_str)
    return;

  /* Test validation function (should not crash) */
  valid = SocketTLSContext_validate_cipher_list (cipher_str);

  /* valid is 0 or 1, just ensuring no crash */
  (void)valid;
}

/**
 * test_ciphersuite_validation - Test TLS 1.3 ciphersuite validation
 * @suite_str: Ciphersuite string to validate
 */
static void
test_ciphersuite_validation (const char *suite_str)
{
  int valid;

  if (!suite_str)
    return;

  /* Test validation function (should not crash) */
  valid = SocketTLSContext_validate_ciphersuites (suite_str);

  /* valid is 0 or 1, just ensuring no crash */
  (void)valid;
}

/**
 * test_cipher_application - Test applying cipher list to context
 * @ctx: TLS context
 * @cipher_str: Cipher string to apply
 */
static void
test_cipher_application (SocketTLSContext_T ctx, const char *cipher_str)
{
  if (!ctx || !cipher_str)
    return;

  TRY { SocketTLSContext_set_cipher_list (ctx, cipher_str); }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid cipher strings */
  }
  END_TRY;
}

/**
 * test_ciphersuite_application - Test applying TLS 1.3 ciphersuites to context
 * @ctx: TLS context
 * @suite_str: Ciphersuite string to apply
 */
static void
test_ciphersuite_application (SocketTLSContext_T ctx, const char *suite_str)
{
  if (!ctx || !suite_str)
    return;

  TRY { SocketTLSContext_set_ciphersuites (ctx, suite_str); }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for invalid ciphersuite strings */
  }
  END_TRY;
}

/**
 * test_with_mutations - Test with mutations of known-valid strings
 * @ctx: TLS context
 * @data: Fuzz data for mutation index
 * @size: Size of fuzz data
 */
static void
test_with_mutations (SocketTLSContext_T ctx, const uint8_t *data, size_t size)
{
  size_t i;
  char mutated[256];
  const char *base;
  size_t base_len;
  size_t mutation_pos;

  if (size < 2)
    return;

  /* Select base string */
  i = data[0] % 7; /* Number of valid cipher strings */
  base = VALID_CIPHER_STRINGS[i];
  if (!base)
    base = VALID_CIPHER_STRINGS[0];

  base_len = strlen (base);
  if (base_len >= sizeof (mutated) - 1)
    return;

  /* Copy and mutate */
  memcpy (mutated, base, base_len);
  mutated[base_len] = '\0';

  /* Apply mutation from fuzz data */
  mutation_pos = data[1] % base_len;
  if (size > 2)
    mutated[mutation_pos] = (char)data[2];

  /* Test mutated string */
  test_cipher_validation (mutated);
  test_cipher_application (ctx, mutated);
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: Cipher string data
 *
 * Tests cipher suite configuration without actual TLS connections.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketTLSContext_T volatile ctx = NULL;
  char *volatile fuzz_str = NULL;

  if (size < 2)
    return 0;

  uint8_t op = data[0];
  const uint8_t *str_data = data + 1;
  size_t str_size = size - 1;

  TRY
  {
    /* Create a minimal client context for testing */
    ctx = SocketTLSContext_new_client (NULL);
    if (!ctx)
      goto cleanup;

    /* Create null-terminated string from fuzz data */
    fuzz_str = null_terminate_fuzz_data (str_data, str_size);

    switch (op % 6)
      {
      case 0:
        /* Test cipher list validation with fuzz data */
        test_cipher_validation (fuzz_str);
        break;

      case 1:
        /* Test TLS 1.3 ciphersuite validation with fuzz data */
        test_ciphersuite_validation (fuzz_str);
        break;

      case 2:
        /* Test applying cipher list to context */
        test_cipher_application ((SocketTLSContext_T)ctx, fuzz_str);
        break;

      case 3:
        /* Test applying TLS 1.3 ciphersuites to context */
        test_ciphersuite_application ((SocketTLSContext_T)ctx, fuzz_str);
        break;

      case 4:
        /* Test with known-valid cipher strings */
        {
          size_t idx = str_size % 7;
          const char *valid = VALID_CIPHER_STRINGS[idx];
          if (valid)
            {
              test_cipher_validation (valid);
              test_cipher_application ((SocketTLSContext_T)ctx, valid);
            }
        }
        break;

      case 5:
        /* Test with mutations of valid strings */
        test_with_mutations ((SocketTLSContext_T)ctx, str_data, str_size);
        break;
      }

    /* Also test TLS 1.3 ciphersuites with some probability */
    if (str_size > 3 && (str_data[0] & 1))
      {
        size_t idx = str_data[1] % 5;
        const char *suite = VALID_TLS13_SUITES[idx];
        if (suite)
          {
            test_ciphersuite_validation (suite);
            test_ciphersuite_application ((SocketTLSContext_T)ctx, suite);
          }
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for many fuzz inputs */
  }
  FINALLY
  {
  cleanup:
    if (fuzz_str)
      free (fuzz_str);
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

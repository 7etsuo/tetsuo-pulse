/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_cert_lookup.c - Fuzzer for TLS Custom Certificate Lookup Callback
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketTLSContext_set_cert_lookup_callback() - Register custom cert lookup
 * - X509_NAME parsing and hashing
 * - Certificate lookup integration with verification
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_tls_cert_lookup Run:   ./fuzz_tls_cert_lookup corpus/tls_cert_lookup/
 * -fork=16 -max_len=4096
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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* Operation codes */
enum CertLookupOp
{
  CERT_LOOKUP_SET_CALLBACK = 0,
  CERT_LOOKUP_SET_NULL_CALLBACK,
  CERT_LOOKUP_X509_NAME_HASH,
  CERT_LOOKUP_OP_COUNT
};

/* Fuzz context for tracking callback invocations */
typedef struct
{
  int callback_count;
  const uint8_t *fuzz_data;
  size_t fuzz_size;
} FuzzLookupContext;

/**
 * fuzz_cert_lookup_callback - Test certificate lookup callback
 * @store_ctx: OpenSSL store context (may be NULL in fuzzing)
 * @name: X509_NAME being looked up
 * @user_data: FuzzLookupContext
 *
 * Simulates certificate lookup with fuzz data. Returns NULL to
 * indicate no certificate found (safe behavior for fuzzing).
 */
static X509 *
fuzz_cert_lookup_callback (X509_STORE_CTX *store_ctx, const X509_NAME *name,
                           void *user_data)
{
  FuzzLookupContext *ctx = (FuzzLookupContext *)user_data;
  (void)store_ctx;

  ctx->callback_count++;

  /* Try to exercise X509_NAME functions with the provided name.
   * Note: Some X509_NAME functions take non-const pointers but the const-cast
   * is safe for read-only operations like hashing. */
  if (name)
    {
      /* X509_NAME_hash takes non-const but doesn't modify */
      unsigned long hash = X509_NAME_hash ((X509_NAME *)name);
      (void)hash;

      char buf[256];
      X509_NAME_oneline ((X509_NAME *)name, buf, sizeof (buf));

      int count = X509_NAME_entry_count ((X509_NAME *)name);
      (void)count;
    }

  /* Return NULL to indicate no certificate found.
   * In a real scenario, we'd return an X509* allocated by us. */
  return NULL;
}

/**
 * fuzz_set_cert_lookup_callback - Test setting the callback
 * @data: Fuzz data (unused, just controls flow)
 * @size: Data size
 *
 * Tests SocketTLSContext_set_cert_lookup_callback() with various inputs.
 */
static int
fuzz_set_cert_lookup_callback (const uint8_t *data, size_t size)
{
  SocketTLSContext_T ctx = NULL;
  FuzzLookupContext fuzz_ctx = { 0, data, size };
  int result = 0;

  TRY
  {
    /* Create client context */
    ctx = SocketTLSContext_new_client (NULL);
    if (!ctx)
      return 0;

    /* Set the callback */
    SocketTLSContext_set_cert_lookup_callback (ctx, fuzz_cert_lookup_callback,
                                               &fuzz_ctx);
    result = 1;

    /* Optionally disable it if fuzz data says so */
    if (size > 0 && (data[0] & 0x01))
      {
        SocketTLSContext_set_cert_lookup_callback (ctx, NULL, NULL);
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    result = 0;
  }
  ELSE
  {
    result = 0;
  }
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);

  return result;
}

/**
 * fuzz_x509_name_hash - Test X509_NAME hashing with fuzz data
 * @data: Fuzz data to use as X509_NAME DER
 * @size: Data size
 *
 * Tests X509_NAME parsing and hashing for lookup operations.
 */
static int
fuzz_x509_name_hash (const uint8_t *data, size_t size)
{
  if (size < 2 || size > INT_MAX)
    return 0;

  /* Try to parse fuzz data as X509_NAME DER */
  const unsigned char *p = data;
  X509_NAME *name = d2i_X509_NAME (NULL, &p, (long)size);

  if (!name)
    return 0;

  /* Exercise X509_NAME functions */
  unsigned long hash = X509_NAME_hash (name);
  (void)hash;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  unsigned long old_hash = X509_NAME_hash_old (name);
  (void)old_hash;
#endif

  char buf[512];
  X509_NAME_oneline (name, buf, sizeof (buf));

  int count = X509_NAME_entry_count (name);
  for (int i = 0; i < count && i < 100; i++)
    {
      X509_NAME_ENTRY *entry = X509_NAME_get_entry (name, i);
      if (entry)
        {
          ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object (entry);
          ASN1_STRING *str = X509_NAME_ENTRY_get_data (entry);
          (void)obj;
          (void)str;
        }
    }

  X509_NAME_free (name);
  return 1;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: Test-specific data
 *
 * Tests certificate lookup callback infrastructure.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  uint8_t op = data[0];
  const uint8_t *test_data = data + 1;
  size_t test_size = size - 1;

  /* Clear any stale OpenSSL errors */
  ERR_clear_error ();

  switch (op % CERT_LOOKUP_OP_COUNT)
    {
    case CERT_LOOKUP_SET_CALLBACK:
      fuzz_set_cert_lookup_callback (test_data, test_size);
      break;

    case CERT_LOOKUP_SET_NULL_CALLBACK:
      {
        SocketTLSContext_T ctx = NULL;
        TRY
        {
          ctx = SocketTLSContext_new_client (NULL);
          if (ctx)
            {
              /* Test setting NULL callback (disable) */
              SocketTLSContext_set_cert_lookup_callback (ctx, NULL, NULL);
            }
        }
        EXCEPT (SocketTLS_Failed) {}
        ELSE {}
        END_TRY;
        if (ctx)
          SocketTLSContext_free (&ctx);
      }
      break;

    case CERT_LOOKUP_X509_NAME_HASH:
      fuzz_x509_name_hash (test_data, test_size);
      break;
    }

  /* Clear errors generated during testing */
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

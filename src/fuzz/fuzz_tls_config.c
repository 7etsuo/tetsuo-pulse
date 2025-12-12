/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_config.c - Fuzzer for TLS Configuration Constants and Validation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets (Section 3.2-3.5 from todo_ssl.md):
 * - SOCKET_TLS13_CIPHERSUITES validation
 * - Timeout configuration validation
 * - Buffer and size limit enforcement
 * - Security limit enforcement
 * - SocketTLSContext_validate_cipher_list()
 * - SocketTLSContext_validate_ciphersuites()
 * - SocketTLS_config_defaults()
 *
 * Security Focus:
 * - Cipher suite string parsing edge cases
 * - Integer overflow in timeout calculations
 * - Buffer size boundary conditions
 * - Configuration limit enforcement
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make fuzz_tls_config
 * Run:   ./fuzz_tls_config corpus/tls_config/ -fork=16 -max_len=4096
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "tls/SocketSSL-internal.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

/* Operation codes for config fuzzing */
enum ConfigOp
{
  CFG_OP_VALIDATE_CIPHERSUITES = 0,
  CFG_OP_VALIDATE_CIPHER_LIST,
  CFG_OP_CONFIG_DEFAULTS,
  CFG_OP_SET_CIPHERSUITES,
  CFG_OP_SET_CIPHER_LIST,
  CFG_OP_SET_MIN_PROTOCOL,
  CFG_OP_SET_MAX_PROTOCOL,
  CFG_OP_ALPN_VALIDATION,
  CFG_OP_SNI_VALIDATION,
  CFG_OP_SESSION_CACHE_SIZE,
  CFG_OP_SESSION_TIMEOUT,
  CFG_OP_VERIFY_CONSTANTS,
  CFG_OP_COUNT
};

/* Test that default constants are within expected ranges */
static void
verify_default_constants (void)
{
  /* Section 3.2: Cipher Suite Defaults */
  assert (SOCKET_TLS13_CIPHERSUITES != NULL);
  assert (strlen (SOCKET_TLS13_CIPHERSUITES) > 0);
  /* Verify order: AES-256-GCM first, ChaCha20 second, AES-128-GCM third */
  assert (strstr (SOCKET_TLS13_CIPHERSUITES, "TLS_AES_256_GCM_SHA384")
          != NULL);
  assert (strstr (SOCKET_TLS13_CIPHERSUITES, "TLS_CHACHA20_POLY1305_SHA256")
          != NULL);
  assert (strstr (SOCKET_TLS13_CIPHERSUITES, "TLS_AES_128_GCM_SHA256") != NULL);
  /* Verify AES-256 comes before ChaCha20 */
  const char *aes256_pos
      = strstr (SOCKET_TLS13_CIPHERSUITES, "TLS_AES_256_GCM_SHA384");
  const char *chacha_pos
      = strstr (SOCKET_TLS13_CIPHERSUITES, "TLS_CHACHA20_POLY1305_SHA256");
  const char *aes128_pos
      = strstr (SOCKET_TLS13_CIPHERSUITES, "TLS_AES_128_GCM_SHA256");
  assert (aes256_pos < chacha_pos);
  assert (chacha_pos < aes128_pos);

  /* Section 3.3: Timeout Configuration */
  assert (SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS == 30000);
  assert (SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS == 5000);
  assert (SOCKET_TLS_POLL_INTERVAL_MS == 100);

  /* Section 3.4: Buffer and Size Limits */
  assert (SOCKET_TLS_BUFFER_SIZE == 16384);
  assert (SOCKET_TLS_MAX_CERT_CHAIN_DEPTH == 10);
  assert (SOCKET_TLS_MAX_ALPN_LEN == 255);
  assert (SOCKET_TLS_MAX_ALPN_TOTAL_BYTES == 1024);
  assert (SOCKET_TLS_MAX_SNI_LEN == 255);
  assert (SOCKET_TLS_SESSION_CACHE_SIZE == 1000);
  assert (SOCKET_TLS_ERROR_BUFSIZE == 512);
  assert (SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE == 256);

  /* Section 3.5: Security Limits */
  assert (SOCKET_TLS_MAX_SNI_CERTS == 100);
  assert (SOCKET_TLS_MAX_PINS == 32);
  assert (SOCKET_TLS_TICKET_KEY_LEN == 80);
  assert (SOCKET_TLS_MAX_OCSP_RESPONSE_LEN == 64 * 1024);
  assert (SOCKET_TLS_MAX_PATH_LEN == 4096);
  assert (SOCKET_TLS_MAX_CRL_SIZE == 10 * 1024 * 1024);
  assert (SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL == 60);
  assert (SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL == 365LL * 24 * 3600);

  /* Section 7.3: Utility Macros */
  /* Verify SOCKET_SSL_UNUSED() macro exists and works correctly */
  {
    int unused_var = 42;
    const char *unused_str = "test";
    void *unused_ptr = NULL;

    /* These should compile without -Wunused-variable warnings */
    SOCKET_SSL_UNUSED (unused_var);
    SOCKET_SSL_UNUSED (unused_str);
    SOCKET_SSL_UNUSED (unused_ptr);

    /* Verify macro expands to (void)(x) pattern */
    /* If this compiles, the macro is working */
  }
}

/* Fuzz cipher suite string validation */
static void
fuzz_ciphersuites (const uint8_t *data, size_t size)
{
  if (size == 0 || size > 2048)
    return;

  /* Create null-terminated string */
  char *ciphersuites = malloc (size + 1);
  if (!ciphersuites)
    return;
  memcpy (ciphersuites, data, size);
  ciphersuites[size] = '\0';

  /* Test validation function - should not crash */
  int valid = SocketTLSContext_validate_ciphersuites (ciphersuites);
  (void)valid; /* Result doesn't matter for fuzzing */

  /* If valid, try setting on a context */
  if (valid)
    {
      TRY
      {
        SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
        if (ctx)
          {
            TRY { SocketTLSContext_set_ciphersuites (ctx, ciphersuites); }
            EXCEPT (SocketTLS_Failed)
            {
              /* Expected for some inputs */
            }
            END_TRY;
            SocketTLSContext_free (&ctx);
          }
      }
      EXCEPT (SocketTLS_Failed)
      {
        /* Context creation failed - ok */
      }
      END_TRY;
    }

  free (ciphersuites);
}

/* Fuzz TLS 1.2 cipher list string validation */
static void
fuzz_cipher_list (const uint8_t *data, size_t size)
{
  if (size == 0 || size > 2048)
    return;

  char *cipher_list = malloc (size + 1);
  if (!cipher_list)
    return;
  memcpy (cipher_list, data, size);
  cipher_list[size] = '\0';

  /* Test validation function */
  int valid = SocketTLSContext_validate_cipher_list (cipher_list);
  (void)valid;

  free (cipher_list);
}

/* Fuzz config defaults initialization */
static void
fuzz_config_defaults (void)
{
  SocketTLSConfig_T config = { 0 };

  /* Should handle NULL gracefully */
  SocketTLS_config_defaults (NULL);

  /* Should set proper defaults */
  SocketTLS_config_defaults (&config);
  assert (config.min_version == SOCKET_TLS_MIN_VERSION);
  assert (config.max_version == SOCKET_TLS_MAX_VERSION);
}

/* Fuzz protocol version settings */
static void
fuzz_protocol_version (const uint8_t *data, size_t size)
{
  if (size < 2)
    return;

  /* Extract version values from fuzzer data */
  int min_version = (int)data[0] << 8;
  if (size > 1)
    min_version |= data[1];

  TRY
  {
    SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
    if (ctx)
      {
        TRY { SocketTLSContext_set_min_protocol (ctx, min_version); }
        EXCEPT (SocketTLS_Failed)
        {
          /* Expected for invalid versions */
        }
        END_TRY;

        if (size > 3)
          {
            int max_version = ((int)data[2] << 8) | data[3];
            TRY { SocketTLSContext_set_max_protocol (ctx, max_version); }
            EXCEPT (SocketTLS_Failed)
            {
              /* Expected for invalid versions */
            }
            END_TRY;
          }

        SocketTLSContext_free (&ctx);
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Context creation failed */
  }
  END_TRY;
}

/* Fuzz session cache configuration */
static void
fuzz_session_cache (const uint8_t *data, size_t size)
{
  if (size < 8)
    return;

  /* Extract cache size and timeout from fuzzer data */
  size_t cache_size = 0;
  long timeout = 0;

  for (int i = 0; i < 4 && i < (int)size; i++)
    cache_size = (cache_size << 8) | data[i];

  for (int i = 4; i < 8 && i < (int)size; i++)
    timeout = (timeout << 8) | data[i];

  TRY
  {
    SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
    if (ctx)
      {
        TRY { SocketTLSContext_enable_session_cache (ctx, cache_size, timeout); }
        EXCEPT (SocketTLS_Failed)
        {
          /* Expected for invalid values */
        }
        END_TRY;

        TRY { SocketTLSContext_set_session_cache_size (ctx, cache_size); }
        EXCEPT (SocketTLS_Failed)
        {
          /* Expected for invalid values */
        }
        END_TRY;

        SocketTLSContext_free (&ctx);
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Context creation failed */
  }
  END_TRY;
}

/* Fuzz ALPN protocol list */
static void
fuzz_alpn_list (const uint8_t *data, size_t size)
{
  if (size < 2)
    return;

  /* First byte is protocol count */
  size_t proto_count = data[0] % 32; /* Limit to reasonable count */
  if (proto_count == 0)
    return;

  /* Allocate protocol array */
  const char **protos = malloc (proto_count * sizeof (char *));
  char **proto_storage = malloc (proto_count * sizeof (char *));
  if (!protos || !proto_storage)
    {
      free (protos);
      free (proto_storage);
      return;
    }

  size_t offset = 1;
  size_t actual_count = 0;

  for (size_t i = 0; i < proto_count && offset < size; i++)
    {
      size_t proto_len = data[offset] % (SOCKET_TLS_MAX_ALPN_LEN + 1);
      offset++;

      if (offset + proto_len > size)
        break;

      proto_storage[i] = malloc (proto_len + 1);
      if (!proto_storage[i])
        break;

      memcpy (proto_storage[i], data + offset, proto_len);
      proto_storage[i][proto_len] = '\0';
      protos[i] = proto_storage[i];
      actual_count++;
      offset += proto_len;
    }

  if (actual_count > 0)
    {
      TRY
      {
        SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
        if (ctx)
          {
            TRY { SocketTLSContext_set_alpn_protos (ctx, protos, actual_count); }
            EXCEPT (SocketTLS_Failed)
            {
              /* Expected for invalid protocols */
            }
            END_TRY;
            SocketTLSContext_free (&ctx);
          }
      }
      EXCEPT (SocketTLS_Failed)
      {
        /* Context creation failed */
      }
      END_TRY;
    }

  /* Cleanup */
  for (size_t i = 0; i < actual_count; i++)
    free (proto_storage[i]);
  free (proto_storage);
  free (protos);
}

/* Main fuzzer entry point */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  /* First byte selects operation */
  enum ConfigOp op = data[0] % CFG_OP_COUNT;
  const uint8_t *rest = data + 1;
  size_t rest_size = size - 1;

  /* Clear OpenSSL error queue to start fresh */
  ERR_clear_error ();

  switch (op)
    {
    case CFG_OP_VALIDATE_CIPHERSUITES:
      fuzz_ciphersuites (rest, rest_size);
      break;

    case CFG_OP_VALIDATE_CIPHER_LIST:
      fuzz_cipher_list (rest, rest_size);
      break;

    case CFG_OP_CONFIG_DEFAULTS:
      fuzz_config_defaults ();
      break;

    case CFG_OP_SET_CIPHERSUITES:
      fuzz_ciphersuites (rest, rest_size);
      break;

    case CFG_OP_SET_CIPHER_LIST:
      fuzz_cipher_list (rest, rest_size);
      break;

    case CFG_OP_SET_MIN_PROTOCOL:
    case CFG_OP_SET_MAX_PROTOCOL:
      fuzz_protocol_version (rest, rest_size);
      break;

    case CFG_OP_ALPN_VALIDATION:
      fuzz_alpn_list (rest, rest_size);
      break;

    case CFG_OP_SNI_VALIDATION:
      /* SNI validation is already covered by fuzz_tls_sni.c */
      break;

    case CFG_OP_SESSION_CACHE_SIZE:
    case CFG_OP_SESSION_TIMEOUT:
      fuzz_session_cache (rest, rest_size);
      break;

    case CFG_OP_VERIFY_CONSTANTS:
      verify_default_constants ();
      break;

    default:
      break;
    }

  /* Clear any errors generated */
  ERR_clear_error ();

  return 0;
}

#else /* !SOCKET_HAS_TLS */

/* Stub when TLS is disabled */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */

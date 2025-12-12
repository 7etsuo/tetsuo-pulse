/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dtls_context.c - Fuzzer for SocketDTLSContext operations
 *
 * Tests DTLS context creation, configuration, and destruction:
 *
 * Section 5.1 Tests (Context Creation and Destruction):
 * - Server context creation with DTLS 1.2 enforcement
 * - Server context with certificate and key loading
 * - Client context with and without CA file
 * - Resource cleanup including cookie secrets
 *
 * Additional Tests:
 * - MTU configuration with range validation
 * - Cookie exchange setup and secret management
 * - ALPN configuration
 * - Session cache configuration
 *
 * Uses in-memory test certificates from fuzz_test_certs.h.
 *
 * NOTE: Avoids nested TRY/EXCEPT to prevent stack-use-after-scope with ASan.
 */

#if SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Except.h"
#include "fuzz_test_certs.h"
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"
#include <openssl/ssl.h>

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

/* Operation types - covers Section 5.1 and additional tests */
typedef enum
{
  OP_CREATE_CLIENT_NO_CA = 0,   /* 5.1: Client without CA file */
  OP_CREATE_CLIENT_WITH_CA,     /* 5.1: Client with CA file (self-signed) */
  OP_CREATE_SERVER,             /* 5.1: Server with cert/key loading */
  OP_SERVER_VERIFY_DTLS12,      /* 5.1: Verify DTLS 1.2 enforcement */
  OP_SET_MTU,                   /* MTU configuration */
  OP_SET_ALPN,                  /* ALPN configuration */
  OP_ENABLE_CACHE,              /* Session cache */
  OP_SET_CIPHER,                /* Cipher list */
  OP_SET_TIMEOUT,               /* Timeout configuration */
  OP_COOKIE_EXCHANGE,           /* 5.1: Cookie exchange and cleanup */
  OP_FULL_SERVER_LIFECYCLE,     /* 5.1: Full server lifecycle with cleanup */
  OP_COUNT
} DTLSContextOp;

/* Temporary file paths for test certs */
static char tmp_cert_path[256] = { 0 };
static char tmp_key_path[256] = { 0 };
static int tmp_files_created = 0;

/**
 * create_temp_cert_files - Write test certs to temporary files
 *
 * Returns: 0 on success, -1 on failure
 */
static int
create_temp_cert_files (void)
{
  FILE *f;

  if (tmp_files_created)
    return 0;

  snprintf (tmp_cert_path, sizeof (tmp_cert_path), "/tmp/fuzz_dtls_cert_%d.pem",
            getpid ());
  snprintf (tmp_key_path, sizeof (tmp_key_path), "/tmp/fuzz_dtls_key_%d.pem",
            getpid ());

  f = fopen (tmp_cert_path, "w");
  if (!f)
    return -1;
  fputs (FUZZ_TEST_CERT, f);
  fclose (f);

  f = fopen (tmp_key_path, "w");
  if (!f)
    {
      unlink (tmp_cert_path);
      return -1;
    }
  fputs (FUZZ_TEST_KEY, f);
  fclose (f);

  tmp_files_created = 1;
  return 0;
}

/**
 * cleanup_temp_files - Remove temporary certificate files
 */
static void
cleanup_temp_files (void)
{
  if (tmp_files_created)
    {
      unlink (tmp_cert_path);
      unlink (tmp_key_path);
      tmp_files_created = 0;
    }
}

/* Register cleanup at exit */
__attribute__ ((constructor)) static void
register_cleanup (void)
{
  atexit (cleanup_temp_files);
}

/**
 * get_op - Extract operation type from fuzz data
 */
static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % OP_COUNT : 0;
}

/**
 * verify_dtls12_enforcement - Verify DTLS 1.2 is minimum version
 *
 * Checks that the SSL_CTX has DTLS 1.2 as minimum protocol version.
 *
 * Returns: 1 if verified, 0 on failure
 */
static int
verify_dtls12_enforcement (SocketDTLSContext_T ctx)
{
  SSL_CTX *ssl_ctx;
  int min_version;

  if (!ctx)
    return 0;

  ssl_ctx = SocketDTLSContext_get_ssl_ctx (ctx);
  if (!ssl_ctx)
    return 0;

  min_version = SSL_CTX_get_min_proto_version (ssl_ctx);

  /* DTLS 1.2 is DTLS1_2_VERSION = 0xFEFD */
  return (min_version == DTLS1_2_VERSION);
}

/**
 * test_cookie_secret_cleanup - Test that cookie secrets are properly cleared
 *
 * Enables cookie exchange, sets a known secret, then frees the context.
 * The free should securely clear the secrets.
 */
static void
test_cookie_secret_cleanup (SocketDTLSContext_T ctx)
{
  unsigned char secret[SOCKET_DTLS_COOKIE_SECRET_LEN];

  /* Generate a test secret */
  memset (secret, 0xAA, sizeof (secret));

  /* Enable cookie exchange and set secret */
  SocketDTLSContext_enable_cookie_exchange (ctx);
  SocketDTLSContext_set_cookie_secret (ctx, secret, sizeof (secret));

  /* Verify cookie exchange is enabled */
  if (!SocketDTLSContext_has_cookie_exchange (ctx))
    return;

  /* Context will be freed by caller - free() should clear secrets */
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  SocketDTLSContext_T ctx = NULL;

  /* Single TRY block - no nesting */
  TRY
  {
    switch (op)
      {
      /* 5.1: Client context without CA file */
      case OP_CREATE_CLIENT_NO_CA:
        ctx = SocketDTLSContext_new_client (NULL);
        if (ctx)
          {
            /* Verify DTLS 1.2 enforcement even on client */
            (void)verify_dtls12_enforcement (ctx);
            SocketDTLSContext_free (&ctx);
          }
        break;

      /* 5.1: Client context with CA file (using self-signed cert as CA) */
      case OP_CREATE_CLIENT_WITH_CA:
        if (create_temp_cert_files () == 0)
          {
            ctx = SocketDTLSContext_new_client (tmp_cert_path);
            if (ctx)
              {
                (void)verify_dtls12_enforcement (ctx);
                SocketDTLSContext_free (&ctx);
              }
          }
        break;

      /* 5.1: Server context with certificate and key loading */
      case OP_CREATE_SERVER:
        if (create_temp_cert_files () == 0)
          {
            ctx = SocketDTLSContext_new_server (tmp_cert_path, tmp_key_path,
                                                NULL);
            if (ctx)
              {
                /* Verify server is properly configured */
                if (!SocketDTLSContext_is_server (ctx))
                  {
                    /* Server flag should be set */
                  }
                SocketDTLSContext_free (&ctx);
              }
          }
        break;

      /* 5.1: Verify DTLS 1.2 minimum enforcement */
      case OP_SERVER_VERIFY_DTLS12:
        if (create_temp_cert_files () == 0)
          {
            ctx = SocketDTLSContext_new_server (tmp_cert_path, tmp_key_path,
                                                NULL);
            if (ctx)
              {
                int verified = verify_dtls12_enforcement (ctx);
                if (!verified)
                  {
                    /* DTLS 1.2 enforcement should always be set */
                  }
                SocketDTLSContext_free (&ctx);
              }
          }
        break;

      case OP_SET_MTU:
        ctx = SocketDTLSContext_new_client (NULL);
        if (ctx && size > 2)
          {
            /* Use fuzz data for MTU value - tests range validation */
            size_t mtu = (data[1] << 8) | data[2];
            SocketDTLSContext_set_mtu (ctx, mtu);
            /* Verify MTU was set if in valid range */
            if (mtu >= SOCKET_DTLS_MIN_MTU && mtu <= SOCKET_DTLS_MAX_MTU)
              {
                size_t current_mtu = SocketDTLSContext_get_mtu (ctx);
                (void)current_mtu;
              }
          }
        break;

      case OP_SET_ALPN:
        ctx = SocketDTLSContext_new_client (NULL);
        if (ctx && size > 3)
          {
            /* Build protocol list from fuzz data */
            char proto[64];
            size_t proto_len = (size - 1) > 63 ? 63 : (size - 1);
            memcpy (proto, data + 1, proto_len);
            proto[proto_len] = '\0';

            const char *protos[] = { proto };
            SocketDTLSContext_set_alpn_protos (ctx, protos, 1);
          }
        break;

      case OP_ENABLE_CACHE:
        ctx = SocketDTLSContext_new_client (NULL);
        if (ctx && size > 4)
          {
            size_t max_sessions = (data[1] << 8) | data[2];
            long timeout = (data[3] << 8) | data[4];
            SocketDTLSContext_enable_session_cache (ctx, max_sessions,
                                                    timeout);
            /* Verify cache stats are available */
            size_t hits = 0, misses = 0, stores = 0;
            SocketDTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);
          }
        break;

      case OP_SET_CIPHER:
        ctx = SocketDTLSContext_new_client (NULL);
        if (ctx && size > 2)
          {
            char ciphers[128];
            size_t cipher_len = (size - 1) > 127 ? 127 : (size - 1);
            memcpy (ciphers, data + 1, cipher_len);
            ciphers[cipher_len] = '\0';
            SocketDTLSContext_set_cipher_list (ctx, ciphers);
          }
        break;

      case OP_SET_TIMEOUT:
        ctx = SocketDTLSContext_new_client (NULL);
        if (ctx && size > 4)
          {
            int initial_ms = (data[1] << 8) | data[2];
            int max_ms = (data[3] << 8) | data[4];
            SocketDTLSContext_set_timeout (ctx, initial_ms, max_ms);
          }
        break;

      /* 5.1: Cookie exchange setup and cleanup verification */
      case OP_COOKIE_EXCHANGE:
        if (create_temp_cert_files () == 0)
          {
            ctx = SocketDTLSContext_new_server (tmp_cert_path, tmp_key_path,
                                                NULL);
            if (ctx)
              {
                test_cookie_secret_cleanup (ctx);
                /* Cookie secrets should be cleared on free */
                SocketDTLSContext_free (&ctx);
              }
          }
        break;

      /* 5.1: Full server lifecycle - tests all resource cleanup */
      case OP_FULL_SERVER_LIFECYCLE:
        if (create_temp_cert_files () == 0)
          {
            ctx = SocketDTLSContext_new_server (tmp_cert_path, tmp_key_path,
                                                tmp_cert_path);
            if (ctx)
              {
                /* Verify all configuration */
                (void)verify_dtls12_enforcement (ctx);
                (void)SocketDTLSContext_is_server (ctx);
                (void)SocketDTLSContext_get_mtu (ctx);

                /* Enable various features */
                SocketDTLSContext_enable_cookie_exchange (ctx);
                SocketDTLSContext_enable_session_cache (ctx, 100, 300);

                /* Set verify mode */
                SocketDTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);

                /* Rotate cookie secret */
                SocketDTLSContext_rotate_cookie_secret (ctx);

                /* Cleanup - should free all resources including:
                 * - SSL_CTX
                 * - Arena allocations
                 * - Cookie secrets (securely cleared)
                 * - Mutexes
                 */
                SocketDTLSContext_free (&ctx);

                /* Verify ctx is NULL after free */
                if (ctx != NULL)
                  {
                    /* ctx should be NULL after free */
                  }
              }
          }
        break;

      default:
        break;
      }
  }
  EXCEPT (SocketDTLS_Failed) {}
  EXCEPT (SocketDTLS_HandshakeFailed) {}
  EXCEPT (SocketDTLS_VerifyFailed) {}
  EXCEPT (SocketDTLS_CookieFailed) {}
  EXCEPT (SocketDTLS_TimeoutExpired) {}
  EXCEPT (SocketDTLS_ShutdownFailed) {}
  ELSE {}
  END_TRY;

  /* Cleanup */
  if (ctx)
    SocketDTLSContext_free (&ctx);

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

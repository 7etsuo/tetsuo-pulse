/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_context.c - TLS Context Creation and Configuration Tests
 *
 * Part of the Socket Library Test Suite (Section 8.1)
 *
 * Tests:
 * 1. Context creation (client and server)
 * 2. Certificate and key loading
 * 3. CA loading
 * 4. Verify mode configuration
 * 5. ALPN protocol configuration
 * 6. Cipher suite configuration
 * 7. Protocol version configuration
 * 8. Context destruction and cleanup
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

/* Suppress -Wclobbered for volatile variables across setjmp/longjmp */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Helper to generate temporary self-signed certificate */
static int
generate_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[1024];

  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=localhost' -batch 2>/dev/null",
            key_file, cert_file);
  if (system (cmd) != 0)
    return -1;

  return 0;
}

static void
remove_test_certs (const char *cert_file, const char *key_file)
{
  unlink (cert_file);
  unlink (key_file);
}

/* ==================== Context Creation Tests ==================== */

TEST (context_create_client)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    /* Create client context without CA */
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLSContext_free (&ctx);
    ASSERT_NULL (ctx);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (context_create_server)
{
  const char *cert_file = "test_ctx_server.crt";
  const char *key_file = "test_ctx_server.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLSContext_free (&ctx);
    ASSERT_NULL (ctx);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (context_free_null_safe)
{
  /* Free NULL should not crash */
  SocketTLSContext_T ctx = NULL;
  SocketTLSContext_free (&ctx);
  ASSERT_NULL (ctx);

  /* Double free should be safe */
  ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);
  SocketTLSContext_free (&ctx);
  ASSERT_NULL (ctx);
  SocketTLSContext_free (&ctx);
  ASSERT_NULL (ctx);
}

/* ==================== Certificate Loading Tests ==================== */

TEST (context_load_certificate)
{
  const char *cert_file = "test_ctx_cert.crt";
  const char *key_file = "test_ctx_cert.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Create server context - loads cert during creation */
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Can also load additional certs */
    SocketTLSContext_load_certificate (ctx, cert_file, key_file);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (context_load_certificate_nonexistent_fails)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    TRY
    {
      ctx = SocketTLSContext_new_server ("/nonexistent/cert.pem",
                                         "/nonexistent/key.pem", NULL);
    }
    EXCEPT (SocketTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== CA Loading Tests ==================== */

TEST (context_load_ca)
{
  const char *cert_file = "test_ctx_ca.crt";
  const char *key_file = "test_ctx_ca.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Load CA certificate */
    SocketTLSContext_load_ca (ctx, cert_file);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (context_load_ca_multiple)
{
  const char *cert1 = "test_ctx_ca1.crt";
  const char *key1 = "test_ctx_ca1.key";
  const char *cert2 = "test_ctx_ca2.crt";
  const char *key2 = "test_ctx_ca2.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert1, key1) != 0)
    return;
  if (generate_test_certs (cert2, key2) != 0)
    {
      remove_test_certs (cert1, key1);
      return;
    }

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Load multiple CAs (should accumulate) */
    SocketTLSContext_load_ca (ctx, cert1);
    SocketTLSContext_load_ca (ctx, cert2);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert1, key1);
    remove_test_certs (cert2, key2);
  }
  END_TRY;
}

/* ==================== Verify Mode Tests ==================== */

TEST (context_verify_mode_none)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (context_verify_mode_peer)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (context_verify_mode_fail_if_no_peer)
{
  const char *cert_file = "test_ctx_verify.crt";
  const char *key_file = "test_ctx_verify.key";
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Server context for mTLS */
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_FAIL_IF_NO_PEER_CERT);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

/* ==================== ALPN Configuration Tests ==================== */

TEST (context_alpn_single_protocol)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    const char *protos[] = {"h2"};
    SocketTLSContext_set_alpn_protos (ctx, protos, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (context_alpn_multiple_protocols)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    const char *protos[] = {"h2", "http/1.1", "spdy/3.1"};
    SocketTLSContext_set_alpn_protos (ctx, protos, 3);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Cipher Suite Configuration Tests ==================== */

TEST (context_cipher_list)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set TLS 1.2 cipher list */
    SocketTLSContext_set_cipher_list (ctx, "ECDHE+AESGCM:DHE+AESGCM");
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (context_ciphersuites_tls13)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set TLS 1.3 ciphersuites */
    SocketTLSContext_set_ciphersuites (
        ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Protocol Version Tests ==================== */

TEST (context_min_protocol_version)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set minimum to TLS 1.3 */
    SocketTLSContext_set_min_protocol (ctx, TLS1_3_VERSION);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (context_max_protocol_version)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set maximum to TLS 1.3 */
    SocketTLSContext_set_max_protocol (ctx, TLS1_3_VERSION);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Helper to generate certificate with specific hostname */
static int
generate_sni_certs (const char *cert_file, const char *key_file,
                    const char *hostname)
{
  char cmd[1024];
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=%s' -batch 2>/dev/null",
            key_file, cert_file, hostname);
  return (system (cmd) == 0) ? 0 : -1;
}

/* ==================== SNI Certificate Tests ==================== */

TEST (context_add_sni_certificate)
{
  const char *cert_file1 = "test_ctx_sni1.crt";
  const char *key_file1 = "test_ctx_sni1.key";
  const char *cert_file2 = "test_ctx_sni2.crt";
  const char *key_file2 = "test_ctx_sni2.key";
  SocketTLSContext_T ctx = NULL;

  /* Generate certificates with matching hostnames */
  if (generate_sni_certs (cert_file1, key_file1, "example.com") != 0)
    return;
  if (generate_sni_certs (cert_file2, key_file2, "test.example.com") != 0)
    {
      remove_test_certs (cert_file1, key_file1);
      return;
    }

  TRY
  {
    /* Use localhost for the default server cert */
    const char *main_cert = "test_ctx_sni_main.crt";
    const char *main_key = "test_ctx_sni_main.key";
    if (generate_test_certs (main_cert, main_key) != 0)
      {
        remove_test_certs (cert_file1, key_file1);
        remove_test_certs (cert_file2, key_file2);
        return;
      }

    ctx = SocketTLSContext_new_server (main_cert, main_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Add certificate for specific hostnames with matching certs */
    SocketTLSContext_add_certificate (ctx, "example.com", cert_file1,
                                      key_file1);
    SocketTLSContext_add_certificate (ctx, "test.example.com", cert_file2,
                                      key_file2);

    remove_test_certs (main_cert, main_key);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file1, key_file1);
    remove_test_certs (cert_file2, key_file2);
  }
  END_TRY;
}

/* ==================== Error Handling Tests ==================== */

TEST (context_invalid_cipher_fails)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    TRY
    {
      SocketTLSContext_set_cipher_list (ctx, "INVALID_CIPHER_THAT_DOES_NOT_EXIST");
    }
    EXCEPT (SocketTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (context_mismatched_cert_key_fails)
{
  const char *cert1 = "test_ctx_mismatch1.crt";
  const char *key1 = "test_ctx_mismatch1.key";
  const char *cert2 = "test_ctx_mismatch2.crt";
  const char *key2 = "test_ctx_mismatch2.key";
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  if (generate_test_certs (cert1, key1) != 0)
    return;
  if (generate_test_certs (cert2, key2) != 0)
    {
      remove_test_certs (cert1, key1);
      return;
    }

  TRY
  {
    /* Try to create context with mismatched cert and key */
    TRY { ctx = SocketTLSContext_new_server (cert1, key2, NULL); }
    EXCEPT (SocketTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert1, key1);
    remove_test_certs (cert2, key2);
  }
  END_TRY;
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

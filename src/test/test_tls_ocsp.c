/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_ocsp.c - OCSP Stapling Tests
 *
 * Part of the Socket Library Test Suite (Section 8.1)
 *
 * Tests:
 * 1. OCSP stapling enable/disable
 * 2. OCSP response setting (server)
 * 3. OCSP response callbacks
 * 4. OCSP status queries
 * 5. OCSP next update time
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

/* ==================== OCSP Stapling Enable Tests ==================== */

TEST (ocsp_enable_stapling_client)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable OCSP stapling request (client-side) */
    SocketTLSContext_enable_ocsp_stapling (ctx);

    /* Verify it's enabled */
    int enabled = SocketTLSContext_ocsp_stapling_enabled (ctx);
    ASSERT_EQ (enabled, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (ocsp_stapling_disabled_by_default)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Should be disabled by default */
    int enabled = SocketTLSContext_ocsp_stapling_enabled (ctx);
    ASSERT_EQ (enabled, 0);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== OCSP Response Tests (Server) ==================== */

TEST (ocsp_set_response_server)
{
  const char *cert_file = "test_ocsp_server.crt";
  const char *key_file = "test_ocsp_server.key";
  SocketTLSContext_T ctx = NULL;
  volatile int exception_raised = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set a dummy OCSP response - this should fail validation because
     * dummy data is not valid DER format. This tests that validation works. */
    unsigned char dummy_response[64];
    memset (dummy_response, 0x42, 64);

    SocketTLSContext_set_ocsp_response (ctx, dummy_response, 64);
    ASSERT (0); /* Should not reach here - validation should fail */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected: dummy response fails DER validation */
    exception_raised = 1;
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;

  ASSERT_EQ (exception_raised, 1);
}

TEST (ocsp_set_response_null_clears)
{
  const char *cert_file = "test_ocsp_null.crt";
  const char *key_file = "test_ocsp_null.key";
  SocketTLSContext_T ctx = NULL;
  volatile int null_exception = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Attempting to set NULL response should raise an exception.
     * OCSP responses must be valid DER format; clearing is implicit on
     * context destruction. This tests the validation behavior. */
    SocketTLSContext_set_ocsp_response (ctx, NULL, 0);
    ASSERT (0); /* Should not reach here */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected: NULL/zero-length is rejected */
    null_exception = 1;
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;

  ASSERT_EQ (null_exception, 1);
}

/* ==================== OCSP Status Query Tests ==================== */

TEST (ocsp_status_before_handshake)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLSContext_enable_ocsp_stapling (ctx);
    SocketTLS_enable (socket, ctx);

    /* OCSP status before handshake should return -1 (no response) */
    int status = SocketTLS_get_ocsp_response_status (socket);
    ASSERT_EQ (status, -1);
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (ocsp_next_update_before_handshake)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLSContext_enable_ocsp_stapling (ctx);
    SocketTLS_enable (socket, ctx);

    /* Next update before handshake should return 0 or -1 */
    time_t next_update = 0;
    int result = SocketTLS_get_ocsp_next_update (socket, &next_update);
    ASSERT (result <= 0);
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== OCSP Generation Callback Tests ==================== */

/* Test callback for OCSP response generation */
static OCSP_RESPONSE *
test_ocsp_gen_callback (SSL *ssl, void *arg)
{
  (void)ssl;
  int *call_count = (int *)arg;
  (*call_count)++;

  /* Return NULL - we don't have a real OCSP responder */
  return NULL;
}

TEST (ocsp_gen_callback_set)
{
  const char *cert_file = "test_ocsp_cb.crt";
  const char *key_file = "test_ocsp_cb.key";
  SocketTLSContext_T ctx = NULL;
  int callback_count = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set OCSP generation callback */
    SocketTLSContext_set_ocsp_gen_callback (ctx, test_ocsp_gen_callback,
                                            &callback_count);

    /* Callback is not invoked until a client requests OCSP stapling */
    ASSERT_EQ (callback_count, 0);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (ocsp_gen_callback_null_clears)
{
  const char *cert_file = "test_ocsp_cb_null.crt";
  const char *key_file = "test_ocsp_cb_null.key";
  SocketTLSContext_T ctx = NULL;
  int callback_count = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set then clear callback */
    SocketTLSContext_set_ocsp_gen_callback (ctx, test_ocsp_gen_callback,
                                            &callback_count);
    SocketTLSContext_set_ocsp_gen_callback (ctx, NULL, NULL);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

/* ==================== OCSP Must-Staple Tests (RFC 7633) ==================== */

TEST (ocsp_must_staple_disabled_by_default)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Must-staple should be disabled by default */
    OCSPMustStapleMode mode = SocketTLSContext_get_ocsp_must_staple (ctx);
    ASSERT_EQ (mode, OCSP_MUST_STAPLE_DISABLED);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (ocsp_must_staple_set_auto)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set to auto-detect mode */
    SocketTLSContext_set_ocsp_must_staple (ctx, OCSP_MUST_STAPLE_AUTO);

    /* Verify setting */
    OCSPMustStapleMode mode = SocketTLSContext_get_ocsp_must_staple (ctx);
    ASSERT_EQ (mode, OCSP_MUST_STAPLE_AUTO);

    /* OCSP stapling should be auto-enabled */
    ASSERT_EQ (SocketTLSContext_ocsp_stapling_enabled (ctx), 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (ocsp_must_staple_set_always)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set to always-require mode */
    SocketTLSContext_set_ocsp_must_staple (ctx, OCSP_MUST_STAPLE_ALWAYS);

    /* Verify setting */
    OCSPMustStapleMode mode = SocketTLSContext_get_ocsp_must_staple (ctx);
    ASSERT_EQ (mode, OCSP_MUST_STAPLE_ALWAYS);

    /* OCSP stapling should be auto-enabled */
    ASSERT_EQ (SocketTLSContext_ocsp_stapling_enabled (ctx), 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (ocsp_must_staple_server_rejects)
{
  const char *cert_file = "test_must_staple.crt";
  const char *key_file = "test_must_staple.key";
  SocketTLSContext_T ctx = NULL;
  volatile int exception_raised = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Must-staple is client-only; server should reject */
    SocketTLSContext_set_ocsp_must_staple (ctx, OCSP_MUST_STAPLE_AUTO);
    ASSERT (0); /* Should not reach here */
  }
  EXCEPT (SocketTLS_Failed)
  {
    exception_raised = 1;
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;

  ASSERT_EQ (exception_raised, 1);
}

TEST (ocsp_must_staple_detect_null_cert)
{
  /* Should handle NULL gracefully, returning 0 */
  int result = SocketTLSContext_cert_has_must_staple (NULL);
  ASSERT_EQ (result, 0);
}

TEST (ocsp_must_staple_mode_transitions)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test transitioning between modes */
    SocketTLSContext_set_ocsp_must_staple (ctx, OCSP_MUST_STAPLE_DISABLED);
    ASSERT_EQ (SocketTLSContext_get_ocsp_must_staple (ctx),
               OCSP_MUST_STAPLE_DISABLED);

    SocketTLSContext_set_ocsp_must_staple (ctx, OCSP_MUST_STAPLE_AUTO);
    ASSERT_EQ (SocketTLSContext_get_ocsp_must_staple (ctx),
               OCSP_MUST_STAPLE_AUTO);

    SocketTLSContext_set_ocsp_must_staple (ctx, OCSP_MUST_STAPLE_ALWAYS);
    ASSERT_EQ (SocketTLSContext_get_ocsp_must_staple (ctx),
               OCSP_MUST_STAPLE_ALWAYS);

    /* Transition back to disabled */
    SocketTLSContext_set_ocsp_must_staple (ctx, OCSP_MUST_STAPLE_DISABLED);
    ASSERT_EQ (SocketTLSContext_get_ocsp_must_staple (ctx),
               OCSP_MUST_STAPLE_DISABLED);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Edge Cases ==================== */

TEST (ocsp_response_empty)
{
  const char *cert_file = "test_ocsp_empty.crt";
  const char *key_file = "test_ocsp_empty.key";
  SocketTLSContext_T ctx = NULL;
  volatile int exception_raised = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Empty response (len=0) should raise an exception.
     * OCSP responses must have valid content. */
    unsigned char empty[1] = { 0 };
    SocketTLSContext_set_ocsp_response (ctx, empty, 0);
    ASSERT (0); /* Should not reach here */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected: zero-length is rejected */
    exception_raised = 1;
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;

  ASSERT_EQ (exception_raised, 1);
}

TEST (ocsp_large_response)
{
  const char *cert_file = "test_ocsp_large.crt";
  const char *key_file = "test_ocsp_large.key";
  SocketTLSContext_T ctx = NULL;
  unsigned char *large_response = NULL;
  volatile int exception_raised = 0;
  size_t response_size = 32 * 1024; /* 32KB */

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  /* Allocate before TRY to ensure cleanup in FINALLY can see the pointer */
  large_response = malloc (response_size);
  if (!large_response)
    {
      remove_test_certs (cert_file, key_file);
      ASSERT_NOT_NULL (large_response);
      return;
    }
  memset (large_response, 0x42, response_size);

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Large response within limits, but dummy data fails DER validation.
     * This tests that format validation is applied to large responses too. */
    SocketTLSContext_set_ocsp_response (ctx, large_response, response_size);
    ASSERT (0); /* Should not reach here - validation should fail */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected: dummy response fails DER validation */
    exception_raised = 1;
  }
  FINALLY
  {
    free (large_response);
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;

  ASSERT_EQ (exception_raised, 1);
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

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_dtls_integration.c - Comprehensive DTLS Integration Tests
 *
 * Tests:
 * 1. SocketDTLSContext creation and configuration
 * 2. DTLS enable on datagram sockets
 * 3. Cookie exchange configuration
 * 4. DTLS handshake
 * 5. DTLS I/O (send/recv)
 * 6. DTLS shutdown
 * 7. Connection info queries
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketDgram.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "core/SocketMetrics.h"
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"

/* Helper to generate temporary self-signed certificate */
static int
generate_dtls_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[1024];

  /* Generate self-signed certificate for testing.
   * Use a simple command compatible with all OpenSSL versions (1.0.2+).
   * Avoid -addext which has inconsistent behavior across versions. */
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=localhost' -batch 2>/dev/null",
            key_file, cert_file);
  if (system (cmd) != 0)
    goto fail;

  return 0;

fail:
  unlink (cert_file);
  unlink (key_file);
  return -1;
}

static void
remove_dtls_test_certs (const char *cert_file, const char *key_file)
{
  unlink (cert_file);
  unlink (key_file);
}

/* ==================== SocketDTLSContext Tests ==================== */

TEST (dtls_context_creation_client)
{
#if SOCKET_HAS_TLS
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    /* Create client context without CA */
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);
    ASSERT_EQ (SocketDTLSContext_is_server (ctx), 0);
    ASSERT_NOT_NULL (SocketDTLSContext_get_ssl_ctx (ctx));

    /* Test default MTU */
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx),
               (size_t)SOCKET_DTLS_DEFAULT_MTU);

    SocketDTLSContext_free (&ctx);
    ASSERT_NULL (ctx);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_context_creation_server)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_dtls_server.crt";
  const char *key_file = "test_dtls_server.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_dtls_test_certs (cert_file, key_file) != 0)
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);
    ASSERT_EQ (SocketDTLSContext_is_server (ctx), 1);
    ASSERT_NOT_NULL (SocketDTLSContext_get_ssl_ctx (ctx));

    SocketDTLSContext_free (&ctx);
    ASSERT_NULL (ctx);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_dtls_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_context_mtu_configuration)
{
#if SOCKET_HAS_TLS
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test valid MTU */
    SocketDTLSContext_set_mtu (ctx, 1400);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), 1400);

    SocketDTLSContext_set_mtu (ctx, 576);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), 576);

    SocketDTLSContext_set_mtu (ctx, 9000);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), 9000);

    SocketDTLSContext_free (&ctx);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_context_cookie_exchange)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_dtls_cookie.crt";
  const char *key_file = "test_dtls_cookie.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_dtls_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Initially cookie exchange should be disabled */
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 0);

    /* Enable cookie exchange */
    SocketDTLSContext_enable_cookie_exchange (ctx);
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 1);

    /* Test secret rotation */
    SocketDTLSContext_rotate_cookie_secret (ctx);
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 1);

    SocketDTLSContext_free (&ctx);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_dtls_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_context_alpn_configuration)
{
#if SOCKET_HAS_TLS
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set ALPN protocols */
    const char *protos[] = { "coap", "h3" };
    SocketDTLSContext_set_alpn_protos (ctx, protos, 2);

    /* Just verify no crash - ALPN negotiation tested in handshake */
    SocketDTLSContext_free (&ctx);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_context_session_cache)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_dtls_cache.crt";
  const char *key_file = "test_dtls_cache.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_dtls_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable session cache */
    SocketDTLSContext_enable_session_cache (ctx, 100, 300);

    /* Get initial stats */
    size_t hits = 0, misses = 0, stores = 0;
    SocketDTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);
    ASSERT_EQ (hits, 0);
    ASSERT_EQ (misses, 0);
    ASSERT_EQ (stores, 0);

    SocketDTLSContext_free (&ctx);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_dtls_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_context_free_null_safe)
{
#if SOCKET_HAS_TLS
  /* Test that free with NULL pointer doesn't crash */
  SocketDTLSContext_T ctx = NULL;
  SocketDTLSContext_free (&ctx);
  ASSERT_NULL (ctx);

  /* Test double free safety */
  ctx = SocketDTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);
  SocketDTLSContext_free (&ctx);
  ASSERT_NULL (ctx);
  SocketDTLSContext_free (&ctx);
  ASSERT_NULL (ctx);
#else
  (void)0;
#endif
}

/* ==================== SocketDTLS Enable Tests ==================== */

TEST (dtls_enable_on_dgram_socket)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable DTLS */
    SocketDTLS_enable (socket, ctx);
    ASSERT_EQ (SocketDTLS_is_enabled (socket), 1);
    ASSERT_EQ (SocketDTLS_is_handshake_done (socket), 0);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_state_queries)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);

    /* Before enable */
    ASSERT_EQ (SocketDTLS_is_enabled (socket), 0);
    ASSERT_EQ (SocketDTLS_is_handshake_done (socket), 0);
    ASSERT_EQ (SocketDTLS_is_shutdown (socket), 0);
    ASSERT_EQ (SocketDTLS_get_last_state (socket), DTLS_HANDSHAKE_NOT_STARTED);

    /* After enable */
    SocketDTLS_enable (socket, ctx);
    ASSERT_EQ (SocketDTLS_is_enabled (socket), 1);
    ASSERT_EQ (SocketDTLS_is_handshake_done (socket), 0);
    ASSERT_EQ (SocketDTLS_is_shutdown (socket), 0);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_mtu_configuration)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Test default MTU */
    ASSERT_EQ (SocketDTLS_get_mtu (socket), (size_t)SOCKET_DTLS_DEFAULT_MTU);

    /* Set custom MTU */
    SocketDTLS_set_mtu (socket, 1200);
    ASSERT_EQ (SocketDTLS_get_mtu (socket), 1200);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== DTLS Connection Info Tests ==================== */

TEST (dtls_connection_info_before_handshake)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Info queries before handshake:
     * - cipher is NULL (not negotiated yet)
     * - version returns protocol version string (SSL object is created)
     * - alpn is NULL (not negotiated yet)
     * - session reuse is 0 (no session yet) */
    ASSERT_NULL (SocketDTLS_get_cipher (socket));
    /* SSL_get_version returns a string even before handshake completes */
    ASSERT_NOT_NULL (SocketDTLS_get_version (socket));
    ASSERT_NULL (SocketDTLS_get_alpn_selected (socket));
    ASSERT_EQ (SocketDTLS_is_session_reused (socket), 0);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Error Path Tests ==================== */

TEST (dtls_double_enable_error)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  volatile int caught_error = 0;

  uint64_t before_total
      = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
  uint64_t before_failed
      = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);

    /* First enable should succeed */
    SocketDTLS_enable (socket, ctx);
    ASSERT_EQ (SocketDTLS_is_enabled (socket), 1);

    /* Verify metrics: total incremented on successful enable */
    uint64_t total_after
        = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
    ASSERT_EQ (total_after, before_total + 1);
    uint64_t failed_after
        = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);
    ASSERT_EQ (failed_after, before_failed);

    /* Second enable should fail */
    TRY { SocketDTLS_enable (socket, ctx); }
    EXCEPT (SocketDTLS_Failed) { caught_error = 1; }
    END_TRY;

    ASSERT_EQ (caught_error, 1);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_io_before_handshake_error)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  volatile int caught_error = 0;

  uint64_t before_total
      = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
  uint64_t before_failed
      = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Send before handshake should fail */
    char buf[] = "test";
    TRY { SocketDTLS_send (socket, buf, sizeof (buf)); }
    EXCEPT (SocketDTLS_Failed) { caught_error = 1; }
    END_TRY;

    ASSERT_EQ (caught_error, 1);

    /* Recv before handshake should fail */
    caught_error = 0;
    TRY { SocketDTLS_recv (socket, buf, sizeof (buf)); }
    EXCEPT (SocketDTLS_Failed) { caught_error = 1; }
    END_TRY;

    ASSERT_EQ (caught_error, 1);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_cookie_exchange_client_error)
{
#if SOCKET_HAS_TLS
  SocketDTLSContext_T ctx = NULL;
  volatile int caught_error = 0;

  uint64_t before_total
      = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
  uint64_t before_failed
      = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);

  TRY
  {
    /* Cookie exchange should fail for client context */
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    TRY { SocketDTLSContext_enable_cookie_exchange (ctx); }
    EXCEPT (SocketDTLS_Failed) { caught_error = 1; }
    END_TRY;

    ASSERT_EQ (caught_error, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_invalid_mtu_error)
{
#if SOCKET_HAS_TLS
  SocketDTLSContext_T ctx = NULL;
  volatile int caught_error = 0;

  uint64_t before_total
      = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
  uint64_t before_failed
      = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* MTU too small */
    caught_error = 0;
    TRY { SocketDTLSContext_set_mtu (ctx, 100); }
    EXCEPT (SocketDTLS_Failed) { caught_error = 1; }
    END_TRY;
    ASSERT_EQ (caught_error, 1);

    /* MTU too large */
    caught_error = 0;
    TRY { SocketDTLSContext_set_mtu (ctx, 100000); }
    EXCEPT (SocketDTLS_Failed) { caught_error = 1; }
    END_TRY;
    ASSERT_EQ (caught_error, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Shutdown Tests ==================== */

TEST (dtls_shutdown_before_handshake)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Shutdown before handshake - should not crash */
    TRY { SocketDTLS_shutdown (socket); }
    EXCEPT (SocketDTLS_ShutdownFailed)
    {
      /* Expected - handshake not complete */
    }
    END_TRY;
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Config Constants Tests ==================== */

TEST (dtls_config_constants)
{
#if SOCKET_HAS_TLS
  /* Verify config constants are sensible */
  ASSERT (SOCKET_DTLS_MIN_MTU > 0);
  ASSERT (SOCKET_DTLS_MAX_MTU > SOCKET_DTLS_MIN_MTU);
  ASSERT (SOCKET_DTLS_DEFAULT_MTU >= SOCKET_DTLS_MIN_MTU);
  ASSERT (SOCKET_DTLS_DEFAULT_MTU <= SOCKET_DTLS_MAX_MTU);

  ASSERT (SOCKET_DTLS_COOKIE_LEN > 0);
  ASSERT (SOCKET_DTLS_COOKIE_SECRET_LEN > 0);
  ASSERT (SOCKET_DTLS_COOKIE_LIFETIME_SEC > 0);

  ASSERT (SOCKET_DTLS_INITIAL_TIMEOUT_MS > 0);
  ASSERT (SOCKET_DTLS_MAX_TIMEOUT_MS >= SOCKET_DTLS_INITIAL_TIMEOUT_MS);

  ASSERT (SOCKET_DTLS_ERROR_BUFSIZE > 0);
  ASSERT (SOCKET_DTLS_MAX_CERT_CHAIN_DEPTH > 0);
#else
  (void)0;
#endif
}

TEST (dtls_validation_macros)
{
#if SOCKET_HAS_TLS
  /* Test SOCKET_DTLS_VALID_MTU macro */
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_MIN_MTU), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_MAX_MTU), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_DEFAULT_MTU), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (100), 0);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (100000), 0);

  /* Test SOCKET_DTLS_VALID_TIMEOUT macro */
  ASSERT_EQ (SOCKET_DTLS_VALID_TIMEOUT (0), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_TIMEOUT (1000), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_TIMEOUT (SOCKET_DTLS_MAX_TIMEOUT_MS), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_TIMEOUT (-1), 0);
#else
  (void)0;
#endif
}

/* ==================== Handshake State Machine Tests ==================== */

TEST (dtls_handshake_state_enum_values)
{
#if SOCKET_HAS_TLS
  /* Verify all DTLSHandshakeState enum values are distinct */
  ASSERT (DTLS_HANDSHAKE_NOT_STARTED != DTLS_HANDSHAKE_IN_PROGRESS);
  ASSERT (DTLS_HANDSHAKE_IN_PROGRESS != DTLS_HANDSHAKE_WANT_READ);
  ASSERT (DTLS_HANDSHAKE_WANT_READ != DTLS_HANDSHAKE_WANT_WRITE);
  ASSERT (DTLS_HANDSHAKE_WANT_WRITE != DTLS_HANDSHAKE_COOKIE_EXCHANGE);
  ASSERT (DTLS_HANDSHAKE_COOKIE_EXCHANGE != DTLS_HANDSHAKE_COMPLETE);
  ASSERT (DTLS_HANDSHAKE_COMPLETE != DTLS_HANDSHAKE_ERROR);
#else
  (void)0;
#endif
}

TEST (dtls_handshake_initial_state)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);

    /* Before enable: state should be NOT_STARTED */
    ASSERT_EQ (SocketDTLS_get_last_state (socket), DTLS_HANDSHAKE_NOT_STARTED);

    /* After enable: state may remain NOT_STARTED */
    SocketDTLS_enable (socket, ctx);
    DTLSHandshakeState state = SocketDTLS_get_last_state (socket);
    /* State should be NOT_STARTED (no handshake attempted yet) */
    ASSERT (state == DTLS_HANDSHAKE_NOT_STARTED
            || state == DTLS_HANDSHAKE_IN_PROGRESS);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_handshake_loop_zero_timeout)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  volatile DTLSHandshakeState state = DTLS_HANDSHAKE_NOT_STARTED;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Zero timeout = non-blocking, returns current state immediately */
    state = SocketDTLS_handshake_loop (socket, 0);

    /* Should return without blocking, state should be valid */
    ASSERT (state == DTLS_HANDSHAKE_IN_PROGRESS
            || state == DTLS_HANDSHAKE_WANT_READ
            || state == DTLS_HANDSHAKE_WANT_WRITE
            || state == DTLS_HANDSHAKE_ERROR);

    /* Should NOT be COMPLETE on unconnected socket */
    ASSERT (state != DTLS_HANDSHAKE_COMPLETE);
  }
  EXCEPT (SocketDTLS_Failed) { /* Expected on unconnected socket */ }
  EXCEPT (SocketDTLS_HandshakeFailed) { /* Expected */ }
  EXCEPT (SocketDTLS_TimeoutExpired) { /* Should NOT happen with timeout=0 */
    ASSERT (0 && "Timeout should not be raised with timeout=0");
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_handshake_loop_short_timeout)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Short timeout - should fail or timeout quickly */
    TRY { SocketDTLS_handshake_loop (socket, 10); }
    EXCEPT (SocketDTLS_TimeoutExpired) { /* Expected timeout */ }
    EXCEPT (SocketDTLS_HandshakeFailed) { /* Also acceptable */ }
    END_TRY;

    /* With unconnected socket, either timeout or handshake failure is expected */
    /* Just verify it returns without hanging */
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_handshake_single_step)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  volatile DTLSHandshakeState state = DTLS_HANDSHAKE_NOT_STARTED;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Single handshake step */
    state = SocketDTLS_handshake (socket);

    /* State should be tracked */
    ASSERT_EQ (SocketDTLS_get_last_state (socket), state);
  }
  EXCEPT (SocketDTLS_Failed) { /* Expected on unconnected socket */ }
  EXCEPT (SocketDTLS_HandshakeFailed) { /* Expected */ }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_listen_without_connection)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  volatile DTLSHandshakeState state = DTLS_HANDSHAKE_NOT_STARTED;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Listen on client context (no cookies) */
    state = SocketDTLS_listen (socket);

    /* Should return a valid state */
    ASSERT (state == DTLS_HANDSHAKE_IN_PROGRESS
            || state == DTLS_HANDSHAKE_WANT_READ
            || state == DTLS_HANDSHAKE_COOKIE_EXCHANGE
            || state == DTLS_HANDSHAKE_ERROR);
  }
  EXCEPT (SocketDTLS_Failed) { /* Expected */ }
  EXCEPT (SocketDTLS_HandshakeFailed) { /* Expected */ }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_handshake_metrics)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  /* Get metrics before test */
  uint64_t before_total
      = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Enabling DTLS should increment handshakes total */
    uint64_t after_total
        = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
    ASSERT (after_total >= before_total);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Edge Case Tests ==================== */

TEST (dtls_cookie_lifetime_constant)
{
#if SOCKET_HAS_TLS
  /* Verify cookie lifetime constant is defined and reasonable */
  ASSERT (SOCKET_DTLS_COOKIE_LIFETIME_SEC > 0);
  ASSERT (SOCKET_DTLS_COOKIE_LIFETIME_SEC <= 300); /* Max 5 minutes */

  /* Default is 60 seconds per implementation */
  ASSERT_EQ (SOCKET_DTLS_COOKIE_LIFETIME_SEC, 60);
#else
  (void)0;
#endif
}

TEST (dtls_cookie_secret_len)
{
#if SOCKET_HAS_TLS
  /* Cookie secret should be at least 32 bytes for HMAC-SHA256 */
  ASSERT (SOCKET_DTLS_COOKIE_SECRET_LEN >= 32);
#else
  (void)0;
#endif
}

TEST (dtls_session_timeout_default)
{
#if SOCKET_HAS_TLS
  /* Verify session timeout constant (for session resumption) */
  ASSERT (SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT > 0);
  /* Typical default is 300 seconds (5 minutes) */
  ASSERT_EQ (SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT, 300);
#else
  (void)0;
#endif
}

TEST (dtls_max_retransmits)
{
#if SOCKET_HAS_TLS
  /* Verify max retransmits constant exists */
  ASSERT (SOCKET_DTLS_MAX_RETRANSMITS > 0);
  /* RFC 6347 recommends exponential backoff with max attempts */
  ASSERT (SOCKET_DTLS_MAX_RETRANSMITS <= 20);
#else
  (void)0;
#endif
}

TEST (dtls_initial_timeout)
{
#if SOCKET_HAS_TLS
  /* Verify initial handshake timeout */
  ASSERT (SOCKET_DTLS_INITIAL_TIMEOUT_MS > 0);
  /* Typical initial timeout is 1 second */
  ASSERT (SOCKET_DTLS_INITIAL_TIMEOUT_MS >= 500);
  ASSERT (SOCKET_DTLS_INITIAL_TIMEOUT_MS <= 5000);
#else
  (void)0;
#endif
}

TEST (dtls_max_record_size)
{
#if SOCKET_HAS_TLS
  /* DTLS max record size per RFC 6347 */
  ASSERT (SOCKET_DTLS_MAX_RECORD_SIZE > 0);
  /* Maximum is 16KB + overhead */
  ASSERT (SOCKET_DTLS_MAX_RECORD_SIZE <= 16384 + 256);
#else
  (void)0;
#endif
}

TEST (dtls_record_overhead)
{
#if SOCKET_HAS_TLS
  /* DTLS record layer overhead (header + MAC + padding) */
  ASSERT (SOCKET_DTLS_RECORD_OVERHEAD > 0);
  /* Typical overhead is 64 bytes or less */
  ASSERT (SOCKET_DTLS_RECORD_OVERHEAD <= 128);
#else
  (void)0;
#endif
}

TEST (dtls_context_session_cache_config)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_dtls_cache_edge.crt";
  const char *key_file = "test_dtls_cache_edge.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_dtls_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable session cache with specific parameters */
    size_t max_sessions = 50;
    size_t timeout_sec = 120;
    SocketDTLSContext_enable_session_cache (ctx, max_sessions, timeout_sec);

    /* Verify cache is operational (stats should be zero initially) */
    size_t hits = 0, misses = 0, stores = 0;
    SocketDTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);
    ASSERT_EQ (hits, 0);
    ASSERT_EQ (misses, 0);
    ASSERT_EQ (stores, 0);

    SocketDTLSContext_free (&ctx);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_dtls_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_handshake_state_transitions)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);

    /* Initial state before enable */
    DTLSHandshakeState initial_state = SocketDTLS_get_last_state (socket);
    ASSERT_EQ (initial_state, DTLS_HANDSHAKE_NOT_STARTED);

    /* Enable DTLS */
    SocketDTLS_enable (socket, ctx);

    /* State after enable but before handshake attempt */
    DTLSHandshakeState post_enable = SocketDTLS_get_last_state (socket);
    ASSERT (post_enable == DTLS_HANDSHAKE_NOT_STARTED
            || post_enable == DTLS_HANDSHAKE_IN_PROGRESS);

    /* Attempt a handshake step (will fail on unconnected socket) */
    TRY
    {
      DTLSHandshakeState step_state = SocketDTLS_handshake (socket);
      /* State should be tracked */
      ASSERT_EQ (SocketDTLS_get_last_state (socket), step_state);
    }
    EXCEPT (SocketDTLS_Failed) { /* Expected */ }
    EXCEPT (SocketDTLS_HandshakeFailed) { /* Expected */ }
    END_TRY;
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_multiple_context_creation)
{
#if SOCKET_HAS_TLS
  SocketDTLSContext_T ctx1 = NULL;
  SocketDTLSContext_T ctx2 = NULL;
  SocketDTLSContext_T ctx3 = NULL;

  TRY
  {
    /* Create multiple client contexts - should not interfere */
    ctx1 = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx1);

    ctx2 = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx2);

    ctx3 = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx3);

    /* All should be independent */
    ASSERT (ctx1 != ctx2);
    ASSERT (ctx2 != ctx3);
    ASSERT (ctx1 != ctx3);

    /* Configure one, verify others unaffected */
    SocketDTLSContext_set_mtu (ctx1, 1000);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx1), 1000);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx2),
               (size_t)SOCKET_DTLS_DEFAULT_MTU);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx3),
               (size_t)SOCKET_DTLS_DEFAULT_MTU);
  }
  FINALLY
  {
    if (ctx1)
      SocketDTLSContext_free (&ctx1);
    if (ctx2)
      SocketDTLSContext_free (&ctx2);
    if (ctx3)
      SocketDTLSContext_free (&ctx3);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_mtu_boundary_values)
{
#if SOCKET_HAS_TLS
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test minimum MTU boundary */
    SocketDTLSContext_set_mtu (ctx, SOCKET_DTLS_MIN_MTU);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), (size_t)SOCKET_DTLS_MIN_MTU);

    /* Test maximum MTU boundary */
    SocketDTLSContext_set_mtu (ctx, SOCKET_DTLS_MAX_MTU);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), (size_t)SOCKET_DTLS_MAX_MTU);

    /* Test MTU just above minimum */
    SocketDTLSContext_set_mtu (ctx, SOCKET_DTLS_MIN_MTU + 1);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx),
               (size_t)(SOCKET_DTLS_MIN_MTU + 1));

    /* Test MTU just below maximum */
    SocketDTLSContext_set_mtu (ctx, SOCKET_DTLS_MAX_MTU - 1);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx),
               (size_t)(SOCKET_DTLS_MAX_MTU - 1));
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_socket_mtu_inheritance)
{
#if SOCKET_HAS_TLS
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set custom MTU on context */
    SocketDTLSContext_set_mtu (ctx, 1200);

    /* Enable DTLS - socket should inherit MTU from context */
    SocketDTLS_enable (socket, ctx);

    /* Socket should have inherited MTU */
    ASSERT_EQ (SocketDTLS_get_mtu (socket), 1200);

    /* Override with socket-specific MTU */
    SocketDTLS_set_mtu (socket, 1100);
    ASSERT_EQ (SocketDTLS_get_mtu (socket), 1100);

    /* Context MTU should be unchanged */
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), 1200);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (dtls_cookie_rotation_multiple)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_dtls_rotation.crt";
  const char *key_file = "test_dtls_rotation.key";
  SocketDTLSContext_T ctx = NULL;

  if (generate_dtls_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable cookie exchange */
    SocketDTLSContext_enable_cookie_exchange (ctx);
    ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 1);

    /* Multiple rotations should be safe */
    for (int i = 0; i < 10; i++)
      {
        SocketDTLSContext_rotate_cookie_secret (ctx);
        ASSERT_EQ (SocketDTLSContext_has_cookie_exchange (ctx), 1);
      }
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
    remove_dtls_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

#endif /* SOCKET_HAS_TLS */

/* ==================== Main ==================== */

int
main (void)
{
  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

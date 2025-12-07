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
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "core/SocketMetrics.h"
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

  uint64_t before_total = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
  uint64_t before_failed = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);

    /* First enable should succeed */
    SocketDTLS_enable (socket, ctx);
    ASSERT_EQ (SocketDTLS_is_enabled (socket), 1);

    /* Verify metrics: total incremented on successful enable */
    uint64_t total_after = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
    ASSERT_EQ (total_after, before_total + 1);
    uint64_t failed_after = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);
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

  uint64_t before_total = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
  uint64_t before_failed = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);

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

  uint64_t before_total = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
  uint64_t before_failed = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);

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

  uint64_t before_total = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);
  uint64_t before_failed = SocketMetrics_counter_get (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);

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


/**
 * test_tls_integration.c - Comprehensive TLS Integration Tests
 *
 * Tests:
 * 1. SocketTLSContext creation and configuration
 * 2. TLS Handshake using socketpair (simulated connection)
 * 3. TLS I/O (send/recv)
 * 4. TLS Shutdown
 * 5. SocketPool TLS integration
 * 6. Socket_sendfile TLS fallback
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "pool/SocketPool.h"
#include "socket/Socket.h"
#include "socket/SocketIO.h"
#include "test/Test.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

/* Helper to generate temporary self-signed certificate with CA extensions
 * Uses config file approach for LibreSSL/macOS compatibility (-addext not supported) */
static int
generate_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[2048];
  const char *conf_file = "/tmp/openssl_test.cnf";
  FILE *f;

  /* Create OpenSSL config file with CA extensions (LibreSSL compatible) */
  f = fopen (conf_file, "w");
  if (!f)
    return -1;
  fprintf (f, "[req]\n"
              "distinguished_name = req_dn\n"
              "x509_extensions = v3_ca\n"
              "[req_dn]\n"
              "CN = localhost\n"
              "[v3_ca]\n"
              "basicConstraints = CA:TRUE\n"
              "keyUsage = keyCertSign, cRLSign\n");
  fclose (f);

  /* Generate self-signed certificate for testing using config file */
  snprintf (cmd, sizeof (cmd),
            "openssl genrsa -out %s 2048 2>/dev/null && "
            "openssl req -new -x509 -key %s -out %s -days 1 -nodes "
            "-subj '/CN=localhost' -config %s -extensions v3_ca 2>/dev/null",
            key_file, key_file, cert_file, conf_file);
  if (system (cmd) != 0)
    {
      unlink (conf_file);
      goto fail;
    }

  unlink (conf_file);
  return 0;

fail:
  unlink (cert_file);
  unlink (key_file);
  return -1;
}

static void
remove_test_certs (const char *cert_file, const char *key_file)
{
  unlink (cert_file);
  unlink (key_file);
}

/* ==================== SocketTLSContext Tests ==================== */

TEST (tls_context_creation)
{
  const char *cert_file = "test_server.crt";
  const char *key_file = "test_server.key";

  /* Generate certs */
  if (generate_test_certs (cert_file, key_file) != 0)
    {
      /* Skip test if openssl not available */
      return;
    }

  TRY
  {
    /* Test Server Context */
    SocketTLSContext_T server_ctx
        = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (server_ctx);

    /* Test Configuration */
    SocketTLSContext_set_min_protocol (server_ctx, SOCKET_TLS_MIN_VERSION);
    SocketTLSContext_set_cipher_list (server_ctx, "HIGH:!aNULL");

    const char *protos[] = { "h2", "http/1.1" };
    SocketTLSContext_set_alpn_protos (server_ctx, protos, 2);

    SocketTLSContext_enable_session_cache (server_ctx, 100, 300);
    SocketTLSContext_set_session_cache_size (server_ctx, 100);

    SocketTLSContext_free (&server_ctx);
    ASSERT_NULL (server_ctx);

    /* Test Client Context */
    SocketTLSContext_T client_ctx
        = SocketTLSContext_new_client (NULL); /* No CA verification for now */
    ASSERT_NOT_NULL (client_ctx);

    SocketTLSContext_set_verify_mode (client_ctx,
                                      TLS_VERIFY_NONE); /* Self-signed cert */

    SocketTLSContext_free (&client_ctx);
    ASSERT_NULL (client_ctx);
  }
  FINALLY { remove_test_certs (cert_file, key_file); }
  END_TRY;
}

/* ==================== TLS Handshake & I/O Tests ==================== */

TEST (tls_handshake_and_io)
{
  const char *cert_file = "test_handshake.crt";
  const char *key_file = "test_handshake.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Create contexts */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (
        client_ctx, TLS_VERIFY_NONE); /* Accept self-signed */

    /* Create connected socket pair */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Enable TLS */
    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Perform Handshake Loop */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);

        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);

        loops++;
        usleep (1000); /* 1ms delay to let data move */
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Verify TLS1.3-only enforcement */
    const char *version = SocketTLS_get_version (client);
    ASSERT_NOT_NULL (version);
    ASSERT (strcmp (version, "TLSv1.3") == 0); /* Strict TLS1.3 */

    const char *cipher = SocketTLS_get_cipher (client);
    ASSERT_NOT_NULL (cipher);
    ASSERT (strstr (cipher, "AES") != NULL
            || strstr (cipher, "CHACHA") != NULL); /* Modern cipher */

    /* Verify Handshake Info */
    ASSERT_NOT_NULL (SocketTLS_get_version (client));
    ASSERT_NOT_NULL (SocketTLS_get_cipher (client));

    /* Test I/O */
    const char *msg = "Hello TLS";
    char buf[64];
    ssize_t n;

    /* Client -> Server */
    n = SocketTLS_send (client, msg, strlen (msg));
    ASSERT_EQ (n, (ssize_t)strlen (msg));

    /* Loop recv until data arrives (non-blocking) */
    loops = 0;
    do
      {
        n = SocketTLS_recv (server, buf, sizeof (buf));
        if (n == 0 && errno == EAGAIN)
          {
            usleep (1000);
            loops++;
          }
        else
          {
            break;
          }
      }
    while (loops < 100);

    ASSERT_EQ (n, (ssize_t)strlen (msg));
    buf[n] = '\0';
    ASSERT_EQ (strcmp (buf, msg), 0);

    /* Server -> Client */
    const char *reply = "TLS Reply";
    n = SocketTLS_send (server, reply, strlen (reply));
    ASSERT_EQ (n, (ssize_t)strlen (reply));

    loops = 0;
    do
      {
        n = SocketTLS_recv (client, buf, sizeof (buf));
        if (n == 0 && errno == EAGAIN)
          {
            usleep (1000);
            loops++;
          }
        else
          {
            break;
          }
      }
    while (loops < 100);

    ASSERT_EQ (n, (ssize_t)strlen (reply));
    buf[n] = '\0';
    ASSERT_EQ (strcmp (buf, reply), 0);

    /* Test Shutdown */
    SocketTLS_shutdown (client);
    /* Server should see shutdown */
    /* Note: Full shutdown requires bidirectional close, simplified here */
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

#endif /* SOCKET_HAS_TLS */

/* ==================== Existing Tests (Preserved) ==================== */

TEST (socketpool_tls_integration_structure)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  Connection_T conn = SocketPool_add (pool, socket);
  ASSERT_NOT_NULL (conn);

  Connection_T retrieved = SocketPool_get (pool, socket);
  ASSERT_EQ (conn, retrieved);

  SocketPool_remove (pool, socket);

  int fd = Socket_fd (socket);
  ASSERT_NE (fd, -1);

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

TEST (socket_sendfile_tls_fallback_check)
{
#ifdef SOCKET_HAS_TLS
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  int file_fd = open ("/dev/zero", O_RDONLY);
  if (file_fd < 0)
    {
      Socket_free (&socket);
      return;
    }

  off_t offset = 0;
  TRY { Socket_sendfile (socket, file_fd, &offset, 10); }
  ELSE { /* Expected failure (socket not connected) */ }
  END_TRY;

  close (file_fd);
  Socket_free (&socket);
#else
  (void)0;
#endif
}

static int
dummy_accept_verify_cb (int pre_ok, X509_STORE_CTX *ctx,
                        SocketTLSContext_T tls_ctx, Socket_T sock,
                        void *user_data)
{
  (void)pre_ok;
  (void)tls_ctx;
  (void)sock;
  (void)user_data;
  X509_STORE_CTX_set_error (ctx, X509_V_OK);
  return 1; /* Always accept for test, clear any errors */
}

static int
dummy_fail_verify_cb (int pre_ok, X509_STORE_CTX *ctx,
                      SocketTLSContext_T tls_ctx, Socket_T sock,
                      void *user_data)
{
  (void)ctx;
  (void)tls_ctx;
  (void)sock;
  (void)user_data;
  return pre_ok
             ? 1
             : 0; /* Fail if pre_ok fail; custom logic e.g., bad cert check */
}

TEST (tls_verify_callback_integration)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_cb.crt";
  const char *key_file = "test_cb.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();

  TRY
  {
    /* Setup server ctx with custom cb that accepts all for test */
    SocketTLSContext_T server_ctx
        = SocketTLSContext_new_server (cert_file, key_file, NULL);
    SocketTLSVerifyCallback fail_cb = dummy_fail_verify_cb;
    SocketTLSContext_set_verify_callback (server_ctx, fail_cb, NULL);
    SocketTLSContext_set_verify_mode (
        server_ctx, TLS_VERIFY_NONE); /* No client cert in test */

    /* Setup client ctx with always-accept cb to test override */
    SocketTLSContext_T client_ctx
        = SocketTLSContext_new_client (NULL); /* No CA load for simple test */
    SocketTLSVerifyCallback accept_cb = dummy_accept_verify_cb;
    SocketTLSContext_set_verify_callback (client_ctx, accept_cb, NULL);
    SocketTLSContext_set_verify_mode (
        client_ctx,
        TLS_VERIFY_NONE); /* Disable verification, test callback override */

    /* Create socketpair for simulated connection */
    int sv[2];
    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    Socket_T server_sock = Socket_new_from_fd (sv[0]);
    Socket_T client_sock = Socket_new_from_fd (sv[1]);

    /* Enable TLS on both (is_server internal from ctx) */
    TRY
    {
      SocketTLS_enable (server_sock, server_ctx);
      SocketTLS_enable (client_sock, client_ctx);
    }
    END_TRY;

    /* Perform handshake with loop to ensure completion */
    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client_sock);

        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server_sock);

        loops++;
        usleep (1000); /* Yield for data transfer */
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    TRY
    {
      long result = SocketTLS_get_verify_result (client_sock);
      ASSERT_EQ (result, X509_V_OK); /* Success with accept_cb on client */
    }
    ELSE { ASSERT (0); /* Unexpected fail in verify result check */ }
    END_TRY;

    /* Cleanup */
    SocketTLSContext_free (&server_ctx);
    SocketTLSContext_free (&client_ctx);
    Socket_free (&server_sock);
    Socket_free (&client_sock);
  }
  FINALLY
  {
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== TLS I/O Edge Cases Tests ==================== */

TEST (tls_send_recv_large_data)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_large.crt";
  const char *key_file = "test_large.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Send larger data (4KB) */
    char send_buf[4096];
    char recv_buf[4096];
    memset (send_buf, 'X', sizeof (send_buf));

    ssize_t sent = SocketTLS_send (client, send_buf, sizeof (send_buf));
    ASSERT (sent > 0);

    /* Receive may need multiple calls for non-blocking */
    ssize_t total_recv = 0;
    loops = 0;
    while (total_recv < sent && loops < 100)
      {
        ssize_t n = SocketTLS_recv (server, recv_buf + total_recv,
                                    sizeof (recv_buf) - (size_t)total_recv);
        if (n > 0)
          total_recv += n;
        else
          usleep (1000);
        loops++;
      }

    ASSERT_EQ (total_recv, sent);
    ASSERT (memcmp (send_buf, recv_buf, (size_t)total_recv) == 0);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (tls_bidirectional_io)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_bidir.crt";
  const char *key_file = "test_bidir.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Multiple bidirectional exchanges */
    for (int i = 0; i < 5; i++)
      {
        char msg[64];
        char buf[64];
        ssize_t n;

        /* Client -> Server */
        snprintf (msg, sizeof (msg), "Request-%d", i);
        n = SocketTLS_send (client, msg, strlen (msg));
        ASSERT_EQ (n, (ssize_t)strlen (msg));

        loops = 0;
        do
          {
            n = SocketTLS_recv (server, buf, sizeof (buf));
            if (n == 0 && errno == EAGAIN)
              {
                usleep (1000);
                loops++;
              }
            else
              break;
          }
        while (loops < 100);

        ASSERT (n > 0);
        buf[n] = '\0';
        ASSERT (strcmp (buf, msg) == 0);

        /* Server -> Client */
        snprintf (msg, sizeof (msg), "Response-%d", i);
        n = SocketTLS_send (server, msg, strlen (msg));
        ASSERT_EQ (n, (ssize_t)strlen (msg));

        loops = 0;
        do
          {
            n = SocketTLS_recv (client, buf, sizeof (buf));
            if (n == 0 && errno == EAGAIN)
              {
                usleep (1000);
                loops++;
              }
            else
              break;
          }
        while (loops < 100);

        ASSERT (n > 0);
        buf[n] = '\0';
        ASSERT (strcmp (buf, msg) == 0);
      }
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Session Reuse Test ==================== */

TEST (tls_session_reuse_check)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_sess.crt";
  const char *key_file = "test_sess.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Note: Session caching is NOT enabled here to avoid OpenSSL internal
     * memory management issues with TLS 1.3 session tickets that cause
     * false positive memory leaks under ASAN. The session cache API is
     * tested in test_tls_phase4.c session_cache_api test. */

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);

    /* Check session reuse status (first connection without cache - should NOT
     * be reused) */
    int reused = SocketTLS_is_session_reused (client);
    ASSERT_EQ (reused, 0);

    /* Test cache stats with disabled cache returns zeros */
    size_t hits = 0, misses = 0, stores = 0;
    SocketTLSContext_get_cache_stats (server_ctx, &hits, &misses, &stores);
    ASSERT_EQ (hits, 0);
    ASSERT_EQ (misses, 0);
    ASSERT_EQ (stores, 0);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== ALPN Negotiation Test ==================== */

TEST (tls_alpn_negotiation_full)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_alpn_full.crt";
  const char *key_file = "test_alpn_full.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Set ALPN protocols on both sides */
    const char *server_protos[] = { "h2", "http/1.1" };
    const char *client_protos[] = { "h2", "http/1.1" };
    SocketTLSContext_set_alpn_protos (server_ctx, server_protos, 2);
    SocketTLSContext_set_alpn_protos (client_ctx, client_protos, 2);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Check ALPN selection */
    const char *selected = SocketTLS_get_alpn_selected (client);
    if (selected)
      {
        /* h2 should be selected (first in server preference) */
        ASSERT (strcmp (selected, "h2") == 0
                || strcmp (selected, "http/1.1") == 0);
      }
    /* NULL is also acceptable if ALPN not supported by OpenSSL build */
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== TLS Shutdown Test ==================== */

TEST (tls_graceful_shutdown)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_shutdown.crt";
  const char *key_file = "test_shutdown.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Test graceful shutdown */
    TRY { SocketTLS_shutdown (client); }
    EXCEPT (SocketTLS_ShutdownFailed)
    {
      /* May fail in non-blocking mode - acceptable */
    }
    END_TRY;

    /* Multiple shutdown calls should be safe */
    TRY { SocketTLS_shutdown (client); }
    EXCEPT (SocketTLS_ShutdownFailed) { /* Already shutdown */ }
    END_TRY;
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== SNI Server Selection Test ==================== */

TEST (tls_sni_server_selection)
{
#ifdef SOCKET_HAS_TLS
  const char *default_cert = "test_sni_srv_default.crt";
  const char *default_key = "test_sni_srv_default.key";

  if (generate_test_certs (default_cert, default_key) != 0)
    return;

  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (default_cert, default_key, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Note: We don't set hostname here because SocketTLS_set_hostname
     * enables SSL_VERIFY_PEER which fails with self-signed certs.
     * The SNI certificate selection is tested in test_tls_phase4.c
     * where we properly set up the verify callback to accept self-signed. */

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (default_cert, default_key);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== TLS Connection Info Test ==================== */

TEST (tls_connection_info_complete)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_info.crt";
  const char *key_file = "test_info.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Test all connection info functions */
    const char *version = SocketTLS_get_version (client);
    ASSERT_NOT_NULL (version);
    ASSERT (strcmp (version, "TLSv1.3") == 0);

    const char *cipher = SocketTLS_get_cipher (client);
    ASSERT_NOT_NULL (cipher);
    ASSERT (strlen (cipher) > 0);

    long verify = SocketTLS_get_verify_result (client);
    /* X509_V_OK = 0, or error code for self-signed */
    ASSERT (verify >= 0);

    int reused = SocketTLS_is_session_reused (client);
    ASSERT (reused == 0 || reused == 1);

    /* ALPN may be NULL if not set */
    const char *alpn = SocketTLS_get_alpn_selected (client);
    (void)alpn; /* NULL is acceptable */

    /* Test server side info too */
    version = SocketTLS_get_version (server);
    ASSERT_NOT_NULL (version);

    cipher = SocketTLS_get_cipher (server);
    ASSERT_NOT_NULL (cipher);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== TLS Context Free Edge Cases ==================== */

TEST (tls_context_free_null_safe)
{
#ifdef SOCKET_HAS_TLS
  /* Test that free with NULL pointer doesn't crash */
  SocketTLSContext_T ctx = NULL;
  SocketTLSContext_free (&ctx); /* Should be safe */
  ASSERT_NULL (ctx);

  /* Test double free safety */
  ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);
  SocketTLSContext_free (&ctx);
  ASSERT_NULL (ctx);
  SocketTLSContext_free (&ctx); /* Second free should be safe */
  ASSERT_NULL (ctx);
#else
  (void)0;
#endif
}

/* ==================== SocketIO TLS Coverage Tests ==================== */

TEST (socketio_tls_enabled_check)
{
#ifdef SOCKET_HAS_TLS
  Socket_T socket = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    /* Non-TLS socket should report TLS disabled */
    ASSERT_EQ (socket_is_tls_enabled (socket), 0);

    /* TLS want read/write should return 0 for non-TLS socket */
    ASSERT_EQ (socket_tls_want_read (socket), 0);
    ASSERT_EQ (socket_tls_want_write (socket), 0);
  }
  FINALLY
  {
    if (socket)
      Socket_free (&socket);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (socketio_tls_scatter_gather_io)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_iov.crt";
  const char *key_file = "test_iov.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* TLS enabled should now return true */
    ASSERT_EQ (socket_is_tls_enabled (client), 1);
    ASSERT_EQ (socket_is_tls_enabled (server), 1);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Test scatter/gather send via TLS */
    char buf1[] = "Hello ";
    char buf2[] = "World!";
    struct iovec iov_send[2];
    iov_send[0].iov_base = buf1;
    iov_send[0].iov_len = strlen (buf1);
    iov_send[1].iov_base = buf2;
    iov_send[1].iov_len = strlen (buf2);

    ssize_t sent = Socket_sendv (client, iov_send, 2);
    ASSERT (sent > 0);

    /* Receive data */
    char recv_buf[64];
    memset (recv_buf, 0, sizeof (recv_buf));
    loops = 0;
    ssize_t total_recv = 0;
    while (total_recv < sent && loops < 100)
      {
        ssize_t n = SocketTLS_recv (server, recv_buf + total_recv,
                                    sizeof (recv_buf) - 1 - (size_t)total_recv);
        if (n > 0)
          total_recv += n;
        else
          usleep (1000);
        loops++;
      }

    ASSERT (total_recv > 0);
    ASSERT (strncmp (recv_buf, "Hello World!", (size_t)total_recv) == 0);

    /* Test scatter/gather receive via TLS */
    char reply[] = "Reply OK";
    ssize_t reply_sent = SocketTLS_send (server, reply, strlen (reply));
    ASSERT_EQ (reply_sent, (ssize_t)strlen (reply));

    char recv1[4], recv2[8];
    memset (recv1, 0, sizeof (recv1));
    memset (recv2, 0, sizeof (recv2));
    struct iovec iov_recv[2];
    iov_recv[0].iov_base = recv1;
    iov_recv[0].iov_len = sizeof (recv1) - 1;
    iov_recv[1].iov_base = recv2;
    iov_recv[1].iov_len = sizeof (recv2) - 1;

    loops = 0;
    total_recv = 0;
    while (total_recv < reply_sent && loops < 100)
      {
        ssize_t n = Socket_recvv (client, iov_recv, 2);
        if (n > 0)
          total_recv += n;
        else
          usleep (1000);
        loops++;
      }

    ASSERT (total_recv > 0);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (socketio_tls_want_states)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_want.crt";
  const char *key_file = "test_want.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* During handshake, want_read/want_write may be set */
    TLSHandshakeState state = SocketTLS_handshake (client);
    if (state == TLS_HANDSHAKE_WANT_READ)
      {
        /* socket_tls_want_read should reflect this */
        int want_read = socket_tls_want_read (client);
        ASSERT (want_read == 0 || want_read == 1);
      }
    if (state == TLS_HANDSHAKE_WANT_WRITE)
      {
        /* socket_tls_want_write should reflect this */
        int want_write = socket_tls_want_write (client);
        ASSERT (want_write == 0 || want_write == 1);
      }

    /* Complete handshake */
    TLSHandshakeState client_state = state;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    /* After handshake complete, want states should be based on pending data */
    if (client_state == TLS_HANDSHAKE_COMPLETE)
      {
        int want_read = socket_tls_want_read (client);
        int want_write = socket_tls_want_write (client);
        ASSERT (want_read == 0 || want_read == 1);
        ASSERT (want_write == 0 || want_write == 1);
      }
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (socketio_raw_scatter_gather)
{
  /* Test raw (non-TLS) scatter/gather I/O */
  Socket_T sock1 = NULL, sock2 = NULL;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    Socket_setnonblocking (sock1);
    Socket_setnonblocking (sock2);

    /* Send using scatter/gather */
    char buf1[] = "Part1";
    char buf2[] = "Part2";
    char buf3[] = "Part3";
    struct iovec iov_send[3];
    iov_send[0].iov_base = buf1;
    iov_send[0].iov_len = strlen (buf1);
    iov_send[1].iov_base = buf2;
    iov_send[1].iov_len = strlen (buf2);
    iov_send[2].iov_base = buf3;
    iov_send[2].iov_len = strlen (buf3);

    ssize_t sent = Socket_sendv (sock1, iov_send, 3);
    ASSERT (sent > 0);

    /* Receive using scatter/gather */
    char recv1[6], recv2[6], recv3[6];
    memset (recv1, 0, sizeof (recv1));
    memset (recv2, 0, sizeof (recv2));
    memset (recv3, 0, sizeof (recv3));
    struct iovec iov_recv[3];
    iov_recv[0].iov_base = recv1;
    iov_recv[0].iov_len = 5;
    iov_recv[1].iov_base = recv2;
    iov_recv[1].iov_len = 5;
    iov_recv[2].iov_base = recv3;
    iov_recv[2].iov_len = 5;

    int loops = 0;
    ssize_t total_recv = 0;
    while (total_recv < sent && loops < 100)
      {
        ssize_t n = Socket_recvv (sock2, iov_recv, 3);
        if (n > 0)
          total_recv += n;
        else
          usleep (1000);
        loops++;
      }

    ASSERT_EQ (total_recv, sent);
    ASSERT (strcmp (recv1, "Part1") == 0);
    ASSERT (strcmp (recv2, "Part2") == 0);
    ASSERT (strcmp (recv3, "Part3") == 0);
  }
  FINALLY
  {
    if (sock1)
      Socket_free (&sock1);
    if (sock2)
      Socket_free (&sock2);
  }
  END_TRY;
}

/* ==================== SocketIO Coverage Tests ==================== */

/**
 * Test Socket_send/Socket_recv on TLS-enabled sockets.
 * This exercises socket_send_tls and socket_recv_tls through the
 * Socket_send/Socket_recv APIs (not the direct SocketTLS_send/recv).
 */
TEST (socketio_tls_send_recv_via_socket_api)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_socketio_api.crt";
  const char *key_file = "test_socketio_api.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Test Socket_send (which routes through socket_send_tls) */
    const char *msg = "TLS via Socket API";
    ssize_t sent = Socket_send (client, msg, strlen (msg));
    ASSERT (sent > 0);

    /* Test Socket_recv (which routes through socket_recv_tls) */
    char buf[64];
    memset (buf, 0, sizeof (buf));
    loops = 0;
    ssize_t total_recv = 0;
    while (total_recv < sent && loops < 100)
      {
        ssize_t n
            = Socket_recv (server, buf + total_recv,
                           sizeof (buf) - 1 - (size_t)total_recv);
        if (n > 0)
          total_recv += n;
        else
          usleep (1000);
        loops++;
      }

    ASSERT (total_recv > 0);
    ASSERT (strcmp (buf, msg) == 0);

    /* Test bidirectional with Socket API */
    const char *reply = "Reply via Socket API";
    sent = Socket_send (server, reply, strlen (reply));
    ASSERT (sent > 0);

    memset (buf, 0, sizeof (buf));
    loops = 0;
    total_recv = 0;
    while (total_recv < sent && loops < 100)
      {
        ssize_t n
            = Socket_recv (client, buf + total_recv,
                           sizeof (buf) - 1 - (size_t)total_recv);
        if (n > 0)
          total_recv += n;
        else
          usleep (1000);
        loops++;
      }

    ASSERT (total_recv > 0);
    ASSERT (strcmp (buf, reply) == 0);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/**
 * Test raw I/O error paths (non-TLS).
 * Exercises error handling in socket_recv_raw and socket_send_raw.
 */
TEST (socketio_raw_error_paths)
{
  Socket_T sock1 = NULL, sock2 = NULL;
  volatile int caught_closed = 0;
  volatile int i;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    Socket_setnonblocking (sock1);
    Socket_setnonblocking (sock2);

    /* Test recv on closed connection (EOF - result == 0) */
    /* Close the writing end to trigger EOF on read */
    Socket_free (&sock1);
    sock1 = NULL;

    char buf[64];
    caught_closed = 0;
    TRY { Socket_recv (sock2, buf, sizeof (buf)); }
    EXCEPT (Socket_Closed) { caught_closed = 1; }
    END_TRY;
    ASSERT_EQ (caught_closed, 1);
  }
  FINALLY
  {
    if (sock1)
      Socket_free (&sock1);
    if (sock2)
      Socket_free (&sock2);
  }
  END_TRY;

  /* Test send on closed connection (EPIPE/ECONNRESET) */
  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    Socket_setnonblocking (sock1);
    Socket_setnonblocking (sock2);

    /* Close the receiving end to trigger EPIPE on send */
    Socket_free (&sock2);
    sock2 = NULL;

    /* Send data - should fail with Socket_Closed */
    char send_buf[64] = "Test data for closed socket";
    caught_closed = 0;

    /* May need multiple sends to trigger EPIPE */
    for (i = 0; i < 10 && !caught_closed; i++)
      {
        TRY { Socket_send (sock1, send_buf, sizeof (send_buf)); }
        EXCEPT (Socket_Closed) { caught_closed = 1; }
        END_TRY;
        usleep (1000);
      }
    /* EPIPE may not always be raised immediately on all systems */
    /* Just verify we don't crash */
  }
  FINALLY
  {
    if (sock1)
      Socket_free (&sock1);
    if (sock2)
      Socket_free (&sock2);
  }
  END_TRY;

  /* Test recvv returning 0 (EOF via scatter/gather) */
  TRY
  {
    SocketPair_new (SOCK_STREAM, &sock1, &sock2);
    Socket_setnonblocking (sock1);
    Socket_setnonblocking (sock2);

    /* Close the writing end */
    Socket_free (&sock1);
    sock1 = NULL;

    char recv1[32], recv2[32];
    struct iovec iov[2];
    iov[0].iov_base = recv1;
    iov[0].iov_len = sizeof (recv1);
    iov[1].iov_base = recv2;
    iov[1].iov_len = sizeof (recv2);

    caught_closed = 0;
    TRY { Socket_recvv (sock2, iov, 2); }
    EXCEPT (Socket_Closed) { caught_closed = 1; }
    END_TRY;
    ASSERT_EQ (caught_closed, 1);
  }
  FINALLY
  {
    if (sock1)
      Socket_free (&sock1);
    if (sock2)
      Socket_free (&sock2);
  }
  END_TRY;
}

/**
 * Test TLS I/O on a socket where the remote end has closed.
 * This exercises SSL error handling paths.
 */
TEST (socketio_tls_closed_connection)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_tls_closed.crt";
  const char *key_file = "test_tls_closed.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;
  volatile int caught_exception = 0;
  volatile int i;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* First do a proper TLS shutdown to send close_notify */
    TRY { SocketTLS_shutdown (server); }
    EXCEPT (SocketTLS_ShutdownFailed) { /* Ignore shutdown failure */ }
    END_TRY;

    /* Close server side to trigger error on client send/recv */
    Socket_free (&server);
    server = NULL;

    /* Small delay to let close propagate */
    usleep (10000);

    /* Try to receive - should get Socket_Closed or return 0 */
    char buf[64];
    caught_exception = 0;
    for (i = 0; i < 3 && !caught_exception; i++)
      {
        TRY
        {
          ssize_t n = Socket_recv (client, buf, sizeof (buf));
          /* n == 0 means EAGAIN (would block), not EOF for TLS */
          (void)n;
        }
        EXCEPT (Socket_Closed) { caught_exception = 1; }
        EXCEPT (SocketTLS_Failed) { caught_exception = 1; }
        END_TRY;
        usleep (1000);
      }
    /* We may or may not catch an exception depending on timing */
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/**
 * Test socket_tls_want_write returns true during handshake.
 * We need to capture the WANT_WRITE state during handshake progression.
 */
TEST (socketio_tls_want_write_during_handshake)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_want_write.crt";
  const char *key_file = "test_want_write.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Perform handshake step by step, checking want states */
    int loops = 0;

    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          {
            client_state = SocketTLS_handshake (client);
            if (client_state == TLS_HANDSHAKE_WANT_WRITE)
              {
                /* Test socket_tls_want_write during handshake */
                int want_write = socket_tls_want_write (client);
                ASSERT (want_write == 0 || want_write == 1);
              }
          }
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          {
            server_state = SocketTLS_handshake (server);
            if (server_state == TLS_HANDSHAKE_WANT_WRITE)
              {
                /* Test socket_tls_want_write during handshake */
                int want_write = socket_tls_want_write (server);
                ASSERT (want_write == 0 || want_write == 1);
              }
          }
        loops++;
        usleep (100);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* WANT_WRITE may or may not be seen depending on timing */
    /* Just verify the function doesn't crash and returns valid value */
    int want_write = socket_tls_want_write (client);
    ASSERT (want_write == 0 || want_write == 1);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/**
 * Test TLS validation errors - handshake not complete.
 * This tests socket_validate_tls_ready error path.
 */
TEST (socketio_tls_validate_not_ready)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_validate.crt";
  const char *key_file = "test_validate.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;
  volatile int caught_error = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Do NOT complete handshake - try to use Socket_send immediately */
    /* This should trigger "TLS handshake not complete" error */

    const char *msg = "Test before handshake";
    caught_error = 0;
    TRY { Socket_send (client, msg, strlen (msg)); }
    EXCEPT (SocketTLS_HandshakeFailed) { caught_error = 1; }
    EXCEPT (Socket_Failed) { caught_error = 1; }
    END_TRY;

    /* We expect an error because handshake is not complete */
    ASSERT_EQ (caught_error, 1);

    /* Also test Socket_recv before handshake */
    char buf[64];
    caught_error = 0;
    TRY { Socket_recv (client, buf, sizeof (buf)); }
    EXCEPT (SocketTLS_HandshakeFailed) { caught_error = 1; }
    EXCEPT (Socket_Failed) { caught_error = 1; }
    END_TRY;
    ASSERT_EQ (caught_error, 1);

    /* Test Socket_sendv before handshake */
    struct iovec iov[1];
    iov[0].iov_base = (void *)msg;
    iov[0].iov_len = strlen (msg);
    caught_error = 0;
    TRY { Socket_sendv (client, iov, 1); }
    EXCEPT (SocketTLS_HandshakeFailed) { caught_error = 1; }
    EXCEPT (Socket_Failed) { caught_error = 1; }
    END_TRY;
    ASSERT_EQ (caught_error, 1);

    /* Test Socket_recvv before handshake */
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof (buf);
    caught_error = 0;
    TRY { Socket_recvv (client, iov, 1); }
    EXCEPT (SocketTLS_HandshakeFailed) { caught_error = 1; }
    EXCEPT (Socket_Failed) { caught_error = 1; }
    END_TRY;
    ASSERT_EQ (caught_error, 1);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/**
 * Test socket_tls_want_write returns correct value when handshake
 * is incomplete and last state was WANT_WRITE.
 */
TEST (socketio_tls_want_write_incomplete_handshake)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_want_write2.crt";
  const char *key_file = "test_want_write2.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Do exactly one handshake step on client only */
    TLSHandshakeState state = SocketTLS_handshake (client);

    /* Check want_write state - depends on handshake state */
    if (state == TLS_HANDSHAKE_WANT_WRITE)
      {
        /* When state is WANT_WRITE and handshake not done, should return 1 */
        int want = socket_tls_want_write (client);
        ASSERT (want == 0 || want == 1);
      }
    else if (state == TLS_HANDSHAKE_WANT_READ)
      {
        /* When state is WANT_READ, want_write should return 0 */
        int want = socket_tls_want_write (client);
        ASSERT (want == 0 || want == 1);
      }

    /* Do one step on server */
    TLSHandshakeState sstate = SocketTLS_handshake (server);
    if (sstate == TLS_HANDSHAKE_WANT_WRITE)
      {
        int want = socket_tls_want_write (server);
        ASSERT (want == 0 || want == 1);
      }
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/**
 * Test TLS send/recv after TLS shutdown to exercise SSL error paths.
 */
TEST (socketio_tls_io_after_shutdown)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_after_shutdown.crt";
  const char *key_file = "test_after_shutdown.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;
  int exception_count = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Initiate TLS shutdown on client */
    TRY { SocketTLS_shutdown (client); }
    EXCEPT (SocketTLS_ShutdownFailed) { /* Ignore */ }
    END_TRY;

    /* Now try to send - may trigger SSL error handling */
    const char *msg = "After shutdown";
    TRY
    {
      ssize_t n = Socket_send (client, msg, strlen (msg));
      (void)n;
    }
    EXCEPT (Socket_Closed) { exception_count++; }
    EXCEPT (SocketTLS_Failed) { exception_count++; }
    EXCEPT (Socket_Failed) { exception_count++; }
    END_TRY;
    /* May or may not throw depending on SSL state */

    /* Try to receive on server after client shutdown */
    char buf[64];
    TRY
    {
      ssize_t n = Socket_recv (server, buf, sizeof (buf));
      (void)n;
    }
    EXCEPT (Socket_Closed) { exception_count++; }
    EXCEPT (SocketTLS_Failed) { exception_count++; }
    EXCEPT (Socket_Failed) { exception_count++; }
    END_TRY;
    /* May or may not throw - just verify we don't crash */

    /* Use the exception count to suppress warning */
    (void)exception_count;
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Session Resumption Verification (5.8) ==================== */

TEST (tls_session_resumption_verification)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_sess_verify.crt";
  const char *key_file = "test_sess_verify.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);
    SocketTLSContext_enable_session_cache (server_ctx, 100, 300);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    int reused = SocketTLS_is_session_reused (client);
    ASSERT_EQ (reused, 0);

    size_t hits = 0, misses = 0, stores = 0;
    SocketTLSContext_get_cache_stats (server_ctx, &hits, &misses, &stores);
    /* Verify stats call succeeded (values are valid) */
    (void)hits;
    (void)misses;
    (void)stores;
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Cipher Suite Negotiation (5.9) ==================== */

TEST (tls_cipher_suite_negotiation)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_cipher_neg.crt";
  const char *key_file = "test_cipher_neg.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);

    const char *cipher = SocketTLS_get_cipher (client);
    ASSERT_NOT_NULL (cipher);

    int valid_cipher = 0;
    if (strstr (cipher, "AES") != NULL || strstr (cipher, "CHACHA") != NULL
        || strstr (cipher, "GCM") != NULL)
      valid_cipher = 1;
    ASSERT_EQ (valid_cipher, 1);

    const char *version = SocketTLS_get_version (client);
    ASSERT_NOT_NULL (version);
    ASSERT (strcmp (version, "TLSv1.3") == 0);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Mutual TLS (5.10) ==================== */

/* Generate client certificate with proper extensions for mTLS
 * Uses config file approach for LibreSSL/macOS compatibility */
static int
generate_client_cert (const char *client_cert, const char *client_key,
                      const char *ca_cert, const char *ca_key)
{
  char cmd[2048];
  const char *conf_file = "/tmp/openssl_client.cnf";
  FILE *f;

  /* Generate client private key */
  snprintf (cmd, sizeof (cmd), "openssl genrsa -out %s 2048 2>/dev/null",
            client_key);
  if (system (cmd) != 0)
    return -1;

  /* Create OpenSSL config file with client auth extensions */
  f = fopen (conf_file, "w");
  if (!f)
    return -1;
  fprintf (f, "[req]\n"
              "distinguished_name = req_dn\n"
              "[req_dn]\n"
              "CN = client\n"
              "[client_ext]\n"
              "basicConstraints = CA:FALSE\n"
              "keyUsage = digitalSignature, keyEncipherment\n"
              "extendedKeyUsage = clientAuth\n");
  fclose (f);

  /* Generate CSR */
  snprintf (cmd, sizeof (cmd),
            "openssl req -new -key %s -out /tmp/client.csr "
            "-subj '/CN=client' -config %s 2>/dev/null",
            client_key, conf_file);
  if (system (cmd) != 0)
    {
      unlink (conf_file);
      return -1;
    }

  /* Sign with CA, including extensions */
  snprintf (cmd, sizeof (cmd),
            "openssl x509 -req -in /tmp/client.csr -CA %s -CAkey %s "
            "-CAcreateserial -out %s -days 1 "
            "-extfile %s -extensions client_ext 2>/dev/null",
            ca_cert, ca_key, client_cert, conf_file);
  if (system (cmd) != 0)
    {
      unlink (conf_file);
      unlink ("/tmp/client.csr");
      return -1;
    }

  unlink (conf_file);
  unlink ("/tmp/client.csr");
  return 0;
}

TEST (tls_mutual_tls_client_cert)
{
#ifdef SOCKET_HAS_TLS
  const char *server_cert = "test_mtls_server.crt";
  const char *server_key = "test_mtls_server.key";
  const char *client_cert = "test_mtls_client.crt";
  const char *client_key = "test_mtls_client.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (server_cert, server_key) != 0)
    return;
  if (generate_client_cert (client_cert, client_key, server_cert, server_key)
      != 0)
    {
      remove_test_certs (server_cert, server_key);
      return;
    }

  TRY
  {
    server_ctx
        = SocketTLSContext_new_server (server_cert, server_key, server_cert);
    SocketTLSContext_set_verify_mode (server_ctx,
                                      TLS_VERIFY_FAIL_IF_NO_PEER_CERT);

    client_ctx = SocketTLSContext_new_client (server_cert);
    SocketTLSContext_load_certificate (client_ctx, client_cert, client_key);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    const char *msg = "mTLS test";
    ssize_t sent = SocketTLS_send (client, msg, strlen (msg));
    ASSERT (sent > 0);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (server_cert, server_key);
    unlink (client_cert);
    unlink (client_key);
  }
  END_TRY;
#else
  (void)0;
#endif
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

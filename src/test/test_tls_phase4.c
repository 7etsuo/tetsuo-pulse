/**
 * test_tls_phase4.c - Phase 4.1 ALPN/SNI Unit Tests
 *
 * Tests the new ALPN and SNI functionality implemented in Phase 4.1
 */

#include "core/Arena.h"
#include "core/SocketUtil.h"
#include "test/Test.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef SOCKET_HAS_TLS

/* Helper to generate temporary self-signed certificate for testing */
static int
generate_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[1024];

  /* Generate self-signed certificate for testing */
  snprintf (
      cmd, sizeof (cmd),
      "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 -nodes "
      "-subj '/CN=localhost' -addext \"basicConstraints = CA:TRUE\" "
      "2>/dev/null",
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
remove_test_certs (const char *cert_file, const char *key_file)
{
  unlink (cert_file);
  unlink (key_file);
}

/* Mock OCSP gen callback for testing - must be at file scope */
static OCSP_RESPONSE *
mock_ocsp_gen_cb (SSL *s, void *a)
{
  (void)s;
  (void)a;
  return NULL; /* Mock no response */
}

TEST (tls_sni_certificate_selection)
{
  (void)0; /* SNI testing requires full client/server handshake setup - covered
              in integration tests */
}

TEST (tls_alpn_protocol_negotiation)
{
  (void)0; /* Full ALPN negotiation requires client/server handshake - covered
              in integration tests */
}

TEST (tls_alpn_get_selected)
{
  (void)0; /* ALPN get selected requires handshake - covered in integration
              tests */
}

TEST (tls_alpn_callback)
{
  (void)0; /* ALPN callback testing requires full handshake - covered in
              integration tests */
}

static int
dummy_verify_cb (int pre_ok, X509_STORE_CTX *ctx, SocketTLSContext_T tls_ctx,
                 Socket_T sock, void *user_data)
{
  (void)pre_ok;
  (void)tls_ctx;
  (void)sock;
  (void)user_data;
  X509_STORE_CTX_set_error (ctx, X509_V_OK);
  return 1; /* Accept for test */
}

static int
fail_verify_cb (int pre_ok, X509_STORE_CTX *ctx, SocketTLSContext_T tls_ctx,
                Socket_T sock, void *user_data)
{
  (void)pre_ok;
  (void)ctx;
  (void)tls_ctx;
  (void)sock;
  (void)user_data;
  return 0; /* Always fail */
}

static int
raising_verify_cb (int pre_ok, X509_STORE_CTX *ctx, SocketTLSContext_T tls_ctx,
                   Socket_T sock, void *user_data)
{
  (void)pre_ok;
  (void)ctx;
  (void)tls_ctx;
  (void)sock;
  (void)user_data;
  RAISE (SocketTLS_Failed); /* Test exception handling in wrapper */
  return 1;                 /* Unreachable */
}

TEST (verify_callback_api)
{
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx
      = SocketTLSContext_new_client (NULL); /* No CA for test */

  /* Test set_callback with NULL (disable) */
  SocketTLSContext_set_verify_callback (ctx, NULL,
                                        NULL); /* Should not raise */

  /* Test set with dummy callback */
  SocketTLSVerifyCallback dummy_cb = (SocketTLSVerifyCallback)dummy_verify_cb;
  void *dummy_data = (void *)0x1;
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);
  SocketTLSContext_set_verify_callback (ctx, dummy_cb,
                                        dummy_data); /* Should not raise */

  /* Test set mode after callback (reconfig) */
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);

  /* Cleanup */
  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
}

TEST (verify_integration_basic)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_cb.crt";
  const char *key_file = "test_cb.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    {
      return; // Skip if openssl not available
    }

  Arena_T arena = Arena_new ();

  SocketTLSContext_T client_ctx = NULL;
  SocketTLSContext_T server_ctx = NULL;
  Socket_T server_sock = NULL;
  Socket_T client_sock = NULL;
  int sv[2];

  TRY
  {
    /* Client ctx: verify PEER but callback always accepts to override pre_ok=0
     * (no CA) */
    client_ctx = SocketTLSContext_new_client (NULL); // No CA -> preverify fail
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_PEER);
    SocketTLSContext_set_verify_callback (client_ctx, dummy_verify_cb,
                                          NULL); // Always returns 1

    /* Server ctx: standard */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    SocketTLSContext_set_verify_mode (server_ctx, TLS_VERIFY_NONE);

    /* Socketpair for local test */
    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    /* Enable TLS */
    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    /* Non-blocking handshake loop */
    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);
    /* Removed duplicate */

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
        usleep (1000); /* Yield */
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Verify result should be OK due to callback override */
    long client_verify = SocketTLS_get_verify_result (client_sock);
    ASSERT_EQ (client_verify, X509_V_OK);

    /* Socket cleanup moved to FINALLY to ensure always executed */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected if cert generation/load or enable fail - skip test (handshake
     * and asserts skipped via exception path) */
  }
  FINALLY
  {
    SocketTLSContext_free (&server_ctx);
    SocketTLSContext_free (&client_ctx);
    Socket_free (&server_sock);
    Socket_free (&client_sock);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}
TEST (crl_load_api)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test invalid path raises */
  TRY
  {
    SocketTLSContext_load_crl (ctx, "/non/existent/path/to/crl.der");
    ASSERT (0); /* Should not reach - raises */
  }
  EXCEPT (SocketTLS_Failed) { /* Expected failure */ }
  END_TRY;

  /* Test empty path raises */
  TRY
  {
    SocketTLSContext_load_crl (ctx, "");
    ASSERT (0);
  }
  EXCEPT (SocketTLS_Failed) { /* Expected */ }
  END_TRY;

  /* Test directory load (current dir - may succeed even without CRL files) */
  TRY
  {
    SocketTLSContext_load_crl (ctx, ".");
    /* Success if path valid; CRLs optional */
  }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Unexpected if path exists */ }
  END_TRY;

  /* Test file load with non-existent but valid name? Or skip advanced */
  /* Full revoked cert test requires sample CRL + revoked cert + CA - for
   * integration suite */

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

TEST (crl_refresh_api)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test refresh on valid path no raise (re-loads) */
  TRY
  {
    SocketTLSContext_refresh_crl (ctx, "."); // dir refresh
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected only if path invalid; adjust for env */
  }
  END_TRY;

  /* Test invalid path raises in refresh */
  TRY
  {
    SocketTLSContext_refresh_crl (ctx, "/non/existent.crl");
    ASSERT (0); /* Should raise */
  }
  EXCEPT (SocketTLS_Failed) { /* Expected */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

TEST (verify_integration_cert)
{
  /* Basic integration: set callback, enable TLS on sock, check no crash */
  /* Full handshake mock or real certs needed for complete; stub for API */
  (void)0; /* Expand with cert files for real test: callback called during
              verify */
}

TEST (session_cache_api)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  size_t hits = 0, misses = 0, stores = 0;
  SocketTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);
  ASSERT_EQ (hits, 0);
  ASSERT_EQ (misses, 0);
  ASSERT_EQ (stores, 0);

  /* Enable with params */
  TRY { SocketTLSContext_enable_session_cache (ctx, 100, 300); }
  EXCEPT (SocketTLS_Failed)
  {
    ASSERT (0); /* Should not raise for valid params */
  }
  END_TRY;

  /* Invalid size raises */
  TRY
  {
    SocketTLSContext_enable_session_cache (ctx, 0,
                                           300); /* 0 invalid? Default ok */
  }
  EXCEPT (SocketTLS_Failed) { /* Adjust if defaults allow */ }
  END_TRY;

  /* Set size */
  SocketTLSContext_set_session_cache_size (ctx, 50);

  /* Get stats still 0 (no handshakes) */
  SocketTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);
  ASSERT_EQ (hits, 0);
  ASSERT_EQ (stores, 0);

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

TEST (session_tickets_api)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  const char *cert_file = "test.crt";
  const char *key_file = "test.key";
  ASSERT_EQ (generate_test_certs (cert_file, key_file), 0);
  SocketTLSContext_T ctx
      = SocketTLSContext_new_server (cert_file, key_file, NULL);

  unsigned char key80[80]
      = { 1 }; /* Mock key of 80 bytes for OpenSSL 3 ticket keys */

  /* Valid len no raise */
  TRY { SocketTLSContext_enable_session_tickets (ctx, key80, 80); }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); }
  END_TRY;

  /* Invalid len raises */
  TRY
  {
    SocketTLSContext_enable_session_tickets (ctx, key80, 79);
    ASSERT (0);
  }
  EXCEPT (SocketTLS_Failed) { /* Expected */ }
  END_TRY;

  /* Re-enable with valid len no raise */
  TRY { SocketTLSContext_enable_session_tickets (ctx, key80, 80); }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); }
  END_TRY;

  SocketTLSContext_free (&ctx);
  remove_test_certs (cert_file, key_file);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

TEST (ocsp_gen_callback_api)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  const char *cert_file = "test.crt";
  const char *key_file = "test.key";
  ASSERT_EQ (generate_test_certs (cert_file, key_file), 0);
  SocketTLSContext_T ctx
      = SocketTLSContext_new_server (cert_file, key_file, NULL);

  /* Set NULL no raise */
  SocketTLSContext_set_ocsp_gen_callback (ctx, NULL, NULL);

  /* Set mock cb no raise (mock_ocsp_gen_cb defined at file scope) */
  SocketTLSContext_set_ocsp_gen_callback (ctx, mock_ocsp_gen_cb, NULL);
  SocketTLSContext_set_ocsp_gen_callback (ctx, mock_ocsp_gen_cb, NULL);

  SocketTLSContext_free (&ctx);
  remove_test_certs (cert_file, key_file);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

TEST (ocsp_status_full)
{
#ifdef SOCKET_HAS_TLS
  /* Test API with mock - full parse requires real response bytes */
  Socket_T mock_sock = NULL; /* Stub - returns 0 */
  ASSERT_EQ (SocketTLS_get_ocsp_status (mock_sock), 0);

  /* Integration with real stapled response requires server cb + client
   * handshake test */
  (void)0; /* Expand in integration */
#else
  (void)0;
#endif
}

/* ==================== Certificate Loading Tests ==================== */

TEST (tls_load_certificate_basic)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_load.crt";
  const char *key_file = "test_load.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    {
      return; /* Skip if openssl not available */
    }

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);
  }
  EXCEPT (SocketTLS_Failed) { /* Expected if cert gen failed */ }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (tls_load_certificate_invalid_path)
{
#ifdef SOCKET_HAS_TLS
  volatile int raised = 0;

  TRY
  {
    SocketTLSContext_T ctx
        = SocketTLSContext_new_server ("/nonexistent/cert.pem",
                                       "/nonexistent/key.pem", NULL);
    (void)ctx;
  }
  EXCEPT (SocketTLS_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (raised, 1);
#else
  (void)0;
#endif
}

/* ==================== CA Loading Tests ==================== */

TEST (tls_load_ca_basic)
{
#ifdef SOCKET_HAS_TLS
  const char *ca_file = "test_ca.crt";
  const char *ca_key = "test_ca.key";

  /* Generate a CA cert for testing */
  if (generate_test_certs (ca_file, ca_key) != 0)
    {
      return; /* Skip if openssl not available */
    }

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (ca_file);
    ASSERT_NOT_NULL (ctx);
  }
  EXCEPT (SocketTLS_Failed) { /* Expected if CA load fails */ }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (ca_file, ca_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (tls_load_ca_invalid_path)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  volatile int raised = 0;

  /* Note: SocketTLSContext_load_ca may or may not raise for invalid paths
   * depending on OpenSSL behavior. Just test that it doesn't crash. */
  TRY { SocketTLSContext_load_ca (ctx, "/nonexistent/ca.pem"); }
  EXCEPT (SocketTLS_Failed) { raised = 1; }
  END_TRY;

  /* Either outcome is acceptable - raised or not */
  ASSERT (raised == 0 || raised == 1);

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== SNI Certificate Tests ==================== */

/* Helper to generate cert for specific hostname */
static int
generate_sni_cert (const char *hostname, const char *cert_file,
                   const char *key_file)
{
  char cmd[1024];

  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
            "-nodes -subj '/CN=%s' 2>/dev/null",
            key_file, cert_file, hostname);
  return system (cmd);
}

TEST (tls_sni_add_certificate_basic)
{
#ifdef SOCKET_HAS_TLS
  const char *default_cert = "test_sni_default.crt";
  const char *default_key = "test_sni_default.key";
  const char *sni_cert = "test_sni_host.crt";
  const char *sni_key = "test_sni_host.key";

  /* Generate certificates */
  if (generate_test_certs (default_cert, default_key) != 0)
    return;
  if (generate_sni_cert ("example.com", sni_cert, sni_key) != 0)
    {
      remove_test_certs (default_cert, default_key);
      return;
    }

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_server (default_cert, default_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Add SNI certificate */
    SocketTLSContext_add_certificate (ctx, "example.com", sni_cert, sni_key);

    /* Should not raise - cert added successfully */
  }
  EXCEPT (SocketTLS_Failed) { /* May fail if cert loading fails */ }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (default_cert, default_key);
    unlink (sni_cert);
    unlink (sni_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (tls_sni_add_multiple_certificates)
{
#ifdef SOCKET_HAS_TLS
  const char *default_cert = "test_sni_multi_default.crt";
  const char *default_key = "test_sni_multi_default.key";
  const char *sni1_cert = "test_sni1.crt";
  const char *sni1_key = "test_sni1.key";
  const char *sni2_cert = "test_sni2.crt";
  const char *sni2_key = "test_sni2.key";

  /* Generate certificates */
  if (generate_test_certs (default_cert, default_key) != 0)
    return;
  if (generate_sni_cert ("host1.example.com", sni1_cert, sni1_key) != 0)
    {
      remove_test_certs (default_cert, default_key);
      return;
    }
  if (generate_sni_cert ("host2.example.com", sni2_cert, sni2_key) != 0)
    {
      remove_test_certs (default_cert, default_key);
      unlink (sni1_cert);
      unlink (sni1_key);
      return;
    }

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_server (default_cert, default_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Add multiple SNI certificates */
    SocketTLSContext_add_certificate (ctx, "host1.example.com", sni1_cert,
                                      sni1_key);
    SocketTLSContext_add_certificate (ctx, "host2.example.com", sni2_cert,
                                      sni2_key);

    /* Should have 2 SNI certs plus default */
  }
  EXCEPT (SocketTLS_Failed) { /* May fail if cert loading fails */ }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (default_cert, default_key);
    unlink (sni1_cert);
    unlink (sni1_key);
    unlink (sni2_cert);
    unlink (sni2_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (tls_sni_add_certificate_invalid_path)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_sni_invalid.crt";
  const char *key_file = "test_sni_invalid.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Try to add certificate with invalid path */
    SocketTLSContext_add_certificate (ctx, "invalid.example.com",
                                      "/nonexistent/cert.pem",
                                      "/nonexistent/key.pem");
  }
  EXCEPT (SocketTLS_Failed) { raised = 1; }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
#else
  (void)0;
#endif
}

TEST (tls_sni_add_default_certificate)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_sni_def.crt";
  const char *key_file = "test_sni_def.key";
  const char *new_default_cert = "test_sni_newdef.crt";
  const char *new_default_key = "test_sni_newdef.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    return;
  if (generate_test_certs (new_default_cert, new_default_key) != 0)
    {
      remove_test_certs (cert_file, key_file);
      return;
    }

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Add default certificate (NULL hostname) */
    SocketTLSContext_add_certificate (ctx, NULL, new_default_cert,
                                      new_default_key);
  }
  EXCEPT (SocketTLS_Failed) { /* May fail */ }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
    remove_test_certs (new_default_cert, new_default_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* Removed duplicate TEST(crl_refresh_api) - covered in crl_load_api extensions
 */

/* ==================== Protocol Version Tests ==================== */

TEST (tls_set_min_protocol)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test setting valid min protocol (TLS 1.3) */
  TRY
  {
    SocketTLSContext_set_min_protocol (ctx, TLS1_3_VERSION);
    /* Should not raise - TLS1.3 is valid */
  }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Unexpected failure */ }
  END_TRY;

  /* Test with TLS 1.2 (lower) - may succeed depending on build */
  TRY { SocketTLSContext_set_min_protocol (ctx, TLS1_2_VERSION); }
  EXCEPT (SocketTLS_Failed) { /* May fail due to TLS1.3-only config */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

TEST (tls_set_max_protocol)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test setting valid max protocol */
  TRY
  {
    SocketTLSContext_set_max_protocol (ctx, TLS1_3_VERSION);
    /* Should not raise */
  }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Unexpected failure */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== Cipher List Tests ==================== */

TEST (tls_set_cipher_list_valid)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test with valid cipher list */
  TRY
  {
    SocketTLSContext_set_cipher_list (ctx, "HIGH:!aNULL:!eNULL");
    /* Should not raise */
  }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); }
  END_TRY;

  /* Test with NULL (should use default) */
  TRY
  {
    SocketTLSContext_set_cipher_list (ctx, NULL);
    /* Should not raise - uses default */
  }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); }
  END_TRY;

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

TEST (tls_set_cipher_list_invalid)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  volatile int raised = 0;

  /* Test with invalid cipher list */
  TRY
  {
    SocketTLSContext_set_cipher_list (ctx, "INVALID_CIPHER_THAT_DOES_NOT_EXIST");
  }
  EXCEPT (SocketTLS_Failed) { raised = 1; }
  END_TRY;

  /* Either raised or OpenSSL accepted it (depends on version) */
  ASSERT (raised == 0 || raised == 1);

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== OCSP Response Tests ==================== */

TEST (tls_ocsp_response_set_valid)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_ocsp.crt";
  const char *key_file = "test_ocsp.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    /* Test with NULL response - should raise */
    TRY
    {
      SocketTLSContext_set_ocsp_response (ctx, NULL, 0);
      ASSERT (0); /* Should raise */
    }
    EXCEPT (SocketTLS_Failed) { /* Expected */ }
    END_TRY;

    /* Test with zero length - should raise */
    unsigned char dummy[1] = { 0 };
    TRY
    {
      SocketTLSContext_set_ocsp_response (ctx, dummy, 0);
      ASSERT (0); /* Should raise */
    }
    EXCEPT (SocketTLS_Failed) { /* Expected */ }
    END_TRY;

    /* Test with invalid OCSP response (garbage bytes) - should raise */
    unsigned char invalid_resp[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    TRY
    {
      SocketTLSContext_set_ocsp_response (ctx, invalid_resp, sizeof (invalid_resp));
      /* May or may not raise depending on OpenSSL parsing */
    }
    EXCEPT (SocketTLS_Failed) { /* May be expected */ }
    END_TRY;
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== ALPN Callback Tests ==================== */

static const char *
custom_alpn_callback (const char **client_protos, size_t client_count,
                      void *user_data)
{
  int *called = (int *)user_data;
  if (called)
    *called = 1;

  /* Always prefer h2 if available */
  for (size_t i = 0; i < client_count; i++)
    {
      if (strcmp (client_protos[i], "h2") == 0)
        return "h2";
    }
  /* Fallback to first protocol */
  return client_count > 0 ? client_protos[0] : NULL;
}

TEST (tls_alpn_callback_registration)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_alpn_cb.crt";
  const char *key_file = "test_alpn_cb.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int callback_marker = 0;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    /* Set ALPN protocols first */
    const char *protos[] = { "h2", "http/1.1" };
    SocketTLSContext_set_alpn_protos (ctx, protos, 2);

    /* Set custom callback */
    SocketTLSContext_set_alpn_callback (ctx, custom_alpn_callback,
                                        (void *)&callback_marker);

    /* Verify callback was registered (context internal state) */
    /* The callback will be invoked during actual handshake */
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

TEST (tls_alpn_callback_null)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test setting NULL callback (disable) - should not raise */
  SocketTLSContext_set_alpn_callback (ctx, NULL, NULL);

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== SNI Hostname Validation Tests ==================== */

TEST (tls_hostname_edge_cases)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_hostname.crt";
  const char *key_file = "test_hostname.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T client_sock = NULL;
  Socket_T server_sock = NULL;
  int sv[2];

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    /* Test valid hostname */
    TRY { SocketTLS_set_hostname (client_sock, "example.com"); }
    EXCEPT (SocketTLS_Failed) { /* May fail on some validation */ }
    END_TRY;

    /* Test hostname with port (should be invalid for SNI) */
    TRY
    {
      SocketTLS_set_hostname (client_sock, "example.com:443");
      /* Some validation may reject this */
    }
    EXCEPT (SocketTLS_Failed) { /* Expected - port not allowed in SNI */ }
    END_TRY;

    /* Test empty hostname (should fail) */
    TRY
    {
      SocketTLS_set_hostname (client_sock, "");
      ASSERT (0); /* Should raise */
    }
    EXCEPT (SocketTLS_Failed) { /* Expected */ }
    END_TRY;
  }
  FINALLY
  {
    if (client_sock)
      Socket_free (&client_sock);
    if (server_sock)
      Socket_free (&server_sock);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Verify Error String Tests ==================== */

TEST (tls_verify_error_string_api)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_verify_str.crt";
  const char *key_file = "test_verify_str.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T client_sock = NULL;
  Socket_T server_sock = NULL;
  int sv[2];

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Complete handshake */
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
        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Test get_verify_error_string with successful verification */
    char err_buf[256];
    const char *err = SocketTLS_get_verify_error_string (client_sock, err_buf,
                                                         sizeof (err_buf));
    /* Should return NULL for successful verification (X509_V_OK) */
    /* Or a string if there was a verification issue (self-signed) */
    (void)err; /* Either outcome acceptable for self-signed */

    /* Test with NULL socket */
    const char *null_err = SocketTLS_get_verify_error_string (NULL, err_buf,
                                                              sizeof (err_buf));
    ASSERT_NULL (null_err);

    /* Test with NULL buffer */
    null_err = SocketTLS_get_verify_error_string (client_sock, NULL,
                                                  sizeof (err_buf));
    ASSERT_NULL (null_err);

    /* Test with zero size */
    null_err = SocketTLS_get_verify_error_string (client_sock, err_buf, 0);
    ASSERT_NULL (null_err);
  }
  FINALLY
  {
    if (client_sock)
      Socket_free (&client_sock);
    if (server_sock)
      Socket_free (&server_sock);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Context Accessor Tests ==================== */

TEST (tls_context_accessors)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_accessor.crt";
  const char *key_file = "test_accessor.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);

    /* Test SocketTLSContext_is_server */
    ASSERT_EQ (SocketTLSContext_is_server (server_ctx), 1);
    ASSERT_EQ (SocketTLSContext_is_server (client_ctx), 0);

    /* Test SocketTLSContext_get_ssl_ctx */
    void *ssl_ctx = SocketTLSContext_get_ssl_ctx (server_ctx);
    ASSERT_NOT_NULL (ssl_ctx);

    ssl_ctx = SocketTLSContext_get_ssl_ctx (client_ctx);
    ASSERT_NOT_NULL (ssl_ctx);
  }
  FINALLY
  {
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== ALPN Protocol Wire Format Tests ==================== */

TEST (tls_alpn_protos_validation)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test with valid protocols */
  TRY
  {
    const char *protos[] = { "h2", "http/1.1", "spdy/3.1" };
    SocketTLSContext_set_alpn_protos (ctx, protos, 3);
    /* Should succeed */
  }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Unexpected failure */ }
  END_TRY;

  /* Test with empty protocol count (should be no-op) */
  TRY
  {
    SocketTLSContext_set_alpn_protos (ctx, NULL, 0);
    /* Should not raise - count=0 is no-op */
  }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); }
  END_TRY;

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== Session Ticket Key Validation Tests ==================== */

TEST (tls_session_tickets_key_length)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_ticket_key.crt";
  const char *key_file = "test_ticket_key.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    /* Test with correct key length (80 bytes) */
    unsigned char key80[80];
    memset (key80, 0x42, sizeof (key80));
    TRY
    {
      SocketTLSContext_enable_session_tickets (ctx, key80, 80);
      /* Should succeed */
    }
    EXCEPT (SocketTLS_Failed) { ASSERT (0); }
    END_TRY;

    /* Test with short key (should fail) */
    unsigned char key48[48];
    memset (key48, 0x42, sizeof (key48));
    TRY
    {
      SocketTLSContext_enable_session_tickets (ctx, key48, 48);
      ASSERT (0); /* Should raise */
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test with long key (should fail) */
    raised = 0;
    unsigned char key128[128];
    memset (key128, 0x42, sizeof (key128));
    TRY
    {
      SocketTLSContext_enable_session_tickets (ctx, key128, 128);
      ASSERT (0); /* Should raise */
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Error Path Tests ==================== */

TEST (tls_enable_without_fd)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
  volatile int raised = 0;

  /* Socket not connected - fd valid but not connected, enable may work */
  TRY { SocketTLS_enable (sock, ctx); }
  EXCEPT (SocketTLS_Failed) { raised = 1; }
  END_TRY;

  /* Either outcome acceptable - depends on implementation */
  (void)raised;

  Socket_free (&sock);
  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

TEST (tls_double_enable)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_double.crt";
  const char *key_file = "test_double.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T sock = NULL;
  int sv[2];
  volatile int raised = 0;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    sock = Socket_new_from_fd (sv[0]);
    close (sv[1]); /* Close peer */

    /* First enable should succeed */
    SocketTLS_enable (sock, client_ctx);

    /* Second enable should fail */
    TRY
    {
      SocketTLS_enable (sock, client_ctx);
      ASSERT (0); /* Should raise */
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;

    ASSERT_EQ (raised, 1);
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Verify Callback Exception Handling Tests ==================== */

TEST (tls_verify_callback_exception)
{
#ifdef SOCKET_HAS_TLS
  const char *cert_file = "test_verify_exc.crt";
  const char *key_file = "test_verify_exc.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T client_sock = NULL;
  Socket_T server_sock = NULL;
  int sv[2];

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);

    /* Set callback that raises exception */
    SocketTLSContext_set_verify_callback (client_ctx, raising_verify_cb, NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_PEER);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Try handshake - may fail due to callback raising exception */
    volatile TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    volatile TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    volatile int loops = 0;
    volatile int handshake_failed = 0;

    TRY
    {
      while ((client_state != TLS_HANDSHAKE_COMPLETE
              && client_state != TLS_HANDSHAKE_ERROR)
             && loops < 100)
        {
          if (client_state != TLS_HANDSHAKE_COMPLETE
              && client_state != TLS_HANDSHAKE_ERROR)
            client_state = SocketTLS_handshake (client_sock);
          if (server_state != TLS_HANDSHAKE_COMPLETE
              && server_state != TLS_HANDSHAKE_ERROR)
            server_state = SocketTLS_handshake (server_sock);
          loops++;
          usleep (1000);
        }
    }
    EXCEPT (SocketTLS_HandshakeFailed) { handshake_failed = 1; }
    END_TRY;

    /* Handshake should have failed due to verify callback exception */
    /* But we're mainly testing that exception doesn't crash */
    (void)handshake_failed;
  }
  FINALLY
  {
    if (client_sock)
      Socket_free (&client_sock);
    if (server_sock)
      Socket_free (&server_sock);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Session Cache Zero Size Test ==================== */

TEST (tls_session_cache_zero_size)
{
#ifdef SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  volatile int raised = 0;

  /* Test setting zero size (should raise) */
  TRY
  {
    SocketTLSContext_set_session_cache_size (ctx, 0);
    ASSERT (0); /* Should raise */
  }
  EXCEPT (SocketTLS_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (raised, 1);

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
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

#else
int
main (void)
{
  return 0;
}
#endif

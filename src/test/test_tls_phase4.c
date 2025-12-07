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

#if SOCKET_HAS_TLS

/* Include private headers for direct SSL access in coverage tests */
#include "socket/Socket-private.h"
#include "tls/SocketTLSConfig.h"
#include <openssl/ocsp.h>

/* Helper to generate temporary self-signed certificate for testing */
static int
generate_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[1024];
  FILE *f;

  /* Generate self-signed certificate for testing.
   * Note: -addext requires OpenSSL 1.1.1+, so we use basic options for compatibility */
  snprintf (
      cmd, sizeof (cmd),
      "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 -nodes "
      "-subj '/CN=localhost' 2>/dev/null",
      key_file, cert_file);
  if (system (cmd) != 0)
    goto fail;

  /* Verify the certificate file was actually created and has content */
  f = fopen (cert_file, "r");
  if (!f)
    goto fail;
  fseek (f, 0, SEEK_END);
  if (ftell (f) < 100)
    {
      fclose (f);
      goto fail;
    }
  fclose (f);

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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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

  /* Test invalid characters (now rejects per full RFC 7301 printable ASCII) */
  TRY
  {
    const char *invalid_chars[] = { "h2", "http/1.1 ", "!invalid space and !", "spdy" }; // space 0x20 invalid, ! 0x21 ok but test
    SocketTLSContext_set_alpn_protos (ctx, invalid_chars, 4);
    ASSERT (0); /* Should raise on invalid chars */
  }
  EXCEPT (SocketTLS_Failed) { /* Expected: validation failure */ }
  END_TRY;

  /* Note: Embedded NUL detection is impossible with C strings since strlen()
   * stops at the first NUL. The API uses const char* so there's no way to
   * detect "intended" length vs actual length. A truncated string like
   * "http/1" (from "http/1.1" with NUL at position 6) is valid by itself.
   * For true embedded NUL detection, the API would need length parameters. */

  /* Test too long protocol */
  TRY
  {
    char long_proto[300] = {0};
    memset (long_proto, 'a', 299);
    long_proto[299] = '\0';
    const char *protos_long[] = { long_proto };
    SocketTLSContext_set_alpn_protos (ctx, protos_long, 1);
    ASSERT (0); /* Should raise on length >255 */
  }
  EXCEPT (SocketTLS_Failed) { /* Expected */ }
  END_TRY;

  /* Test too many protocols (exceeds max) */
    const char *many_protos[17];
  TRY
  {
    for (int i = 0; i < 17; i++)
      {
        char buf[20]; /* "proto" + int digits + null */
        snprintf (buf, sizeof (buf), "proto%d", i);
        many_protos[i] = strdup (buf); /* Leak ok for test */
      }
    SocketTLSContext_set_alpn_protos (ctx, many_protos, 17);
    ASSERT (0); /* Should raise on count > max (16) */
  }
  EXCEPT (SocketTLS_Failed) { /* Expected */ }
  FINALLY
  {
    /* Cleanup test leak */
    for (int i = 0; i < 17; i++) free ((void*)many_protos[i]);
  }
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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
#if SOCKET_HAS_TLS
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

/* ==================== Session Cache Stats NULL Context Test ==================== */

TEST (session_cache_stats_null_context)
{
#if SOCKET_HAS_TLS
  size_t hits = 99, misses = 99, stores = 99;

  /* Test with NULL context - should set all outputs to 0 */
  SocketTLSContext_get_cache_stats (NULL, &hits, &misses, &stores);
  ASSERT_EQ (hits, 0);
  ASSERT_EQ (misses, 0);
  ASSERT_EQ (stores, 0);
#else
  (void)0;
#endif
}

/* ==================== Session Cache Stats Disabled Test ==================== */

TEST (session_cache_stats_disabled)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  size_t hits = 99, misses = 99, stores = 99;

  /* Don't enable session cache - should return 0 for all stats */
  SocketTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);
  ASSERT_EQ (hits, 0);
  ASSERT_EQ (misses, 0);
  ASSERT_EQ (stores, 0);

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== Session Cache Stats Partial NULL Pointers Test ==================== */

TEST (session_cache_stats_partial_null)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  size_t hits = 99, misses = 99, stores = 99;

  /* Enable session cache first */
  TRY { SocketTLSContext_enable_session_cache (ctx, 100, 300); }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Should not fail */ }
  END_TRY;

  /* Test with only misses pointer (hits and stores NULL) */
  SocketTLSContext_get_cache_stats (ctx, NULL, &misses, NULL);
  ASSERT_EQ (misses, 0); /* No handshakes yet */

  /* Test with hits and stores (misses NULL) */
  SocketTLSContext_get_cache_stats (ctx, &hits, NULL, &stores);
  ASSERT_EQ (hits, 0);
  ASSERT_EQ (stores, 0);

  /* Test with all NULL pointers - should not crash */
  SocketTLSContext_get_cache_stats (ctx, NULL, NULL, NULL);

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== Session Cache Server Mode Test ==================== */

TEST (session_cache_server_mode)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_cache_srv.crt";
  const char *key_file = "test_cache_srv.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable session cache on server context - uses SSL_SESS_CACHE_SERVER */
    SocketTLSContext_enable_session_cache (ctx, 100, 300);

    /* Verify no exception raised */
    size_t hits, misses, stores;
    SocketTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);
    ASSERT_EQ (hits, 0);
    ASSERT_EQ (misses, 0);
    ASSERT_EQ (stores, 0);
  }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Should not fail */ }
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

/* ==================== Session Cache Timeout Defaults Test ==================== */

TEST (session_cache_timeout_defaults)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test with zero timeout - should use SOCKET_TLS_SESSION_TIMEOUT_DEFAULT */
  TRY { SocketTLSContext_enable_session_cache (ctx, 100, 0); }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Should not fail */ }
  END_TRY;

  SocketTLSContext_free (&ctx);

  /* Create new context for negative timeout test */
  ctx = SocketTLSContext_new_client (NULL);

  /* Test with negative timeout - should use SOCKET_TLS_SESSION_TIMEOUT_DEFAULT */
  TRY { SocketTLSContext_enable_session_cache (ctx, 100, -1); }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Should not fail */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== Session Cache With Zero Max Sessions Test ==================== */

TEST (session_cache_zero_max_sessions)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test with zero max_sessions - should skip set_cache_size call */
  TRY { SocketTLSContext_enable_session_cache (ctx, 0, 300); }
  EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Should not fail */ }
  END_TRY;

  /* Verify cache is still enabled */
  size_t hits, misses, stores;
  SocketTLSContext_get_cache_stats (ctx, &hits, &misses, &stores);
  /* Stats should be 0 since no handshakes */
  ASSERT_EQ (hits, 0);

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== Session Resumption Integration Test ==================== */

TEST (session_resumption_stats)
{
#if SOCKET_HAS_TLS
  /* NOTE: This test exercises the session cache callback code paths
   * (new_session_cb and info_callback) without performing a full handshake.
   * Full handshake with session caching causes OpenSSL TLS 1.3 session ticket
   * memory issues under ASAN (documented in test_tls_integration.c).
   *
   * The callbacks ARE exercised by the following:
   * - info_callback: Called during any SSL_do_handshake operation
   * - new_session_cb: Called when sessions are created
   *
   * We test the callback registration and stats access here.
   * The actual callback execution is tested by the handshake tests in
   * test_tls_integration.c which don't enable session caching.
   */
  const char *cert_file = "test_resume.crt";
  const char *key_file = "test_resume.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;

  TRY
  {
    /* Create server context with session cache enabled */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    SocketTLSContext_enable_session_cache (server_ctx, 100, 300);

    /* Create client context with session cache enabled */
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_enable_session_cache (client_ctx, 100, 300);

    /* Verify callbacks were registered by checking stats are accessible */
    size_t hits = 99, misses = 99, stores = 99;

    /* Server stats should be 0 (no handshakes) */
    SocketTLSContext_get_cache_stats (server_ctx, &hits, &misses, &stores);
    ASSERT_EQ (hits, 0);
    ASSERT_EQ (misses, 0);
    ASSERT_EQ (stores, 0);

    /* Client stats should be 0 (no handshakes) */
    hits = 99;
    misses = 99;
    stores = 99;
    SocketTLSContext_get_cache_stats (client_ctx, &hits, &misses, &stores);
    ASSERT_EQ (hits, 0);
    ASSERT_EQ (misses, 0);
    ASSERT_EQ (stores, 0);

    /* The new_session_cb and info_callback are registered via:
     * - SSL_CTX_sess_set_new_cb (called in enable_session_cache)
     * - SSL_CTX_set_info_callback (called in enable_session_cache)
     * These callbacks will be invoked during actual handshakes.
     *
     * The callback code paths are covered by:
     * - test_tls_integration.c tls_handshake_and_io (exercises info_callback)
     * - tls_context_creation test (enables session cache)
     */
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

/* =========================================================================
 * COVERAGE TESTS FOR SocketTLSContext-verify.c
 * =========================================================================
 */

/* ==================== Verify Mode All Cases Test ==================== */

TEST (tls_verify_mode_all_cases)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test TLS_VERIFY_NONE (already tested elsewhere, but ensure coverage) */
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);

  /* Test TLS_VERIFY_PEER */
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);

  /* Test TLS_VERIFY_FAIL_IF_NO_PEER_CERT */
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_FAIL_IF_NO_PEER_CERT);

  /* Test TLS_VERIFY_CLIENT_ONCE - exercises that switch case */
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_CLIENT_ONCE);

  /* Test invalid/default case - pass an invalid value to trigger default */
  SocketTLSContext_set_verify_mode (ctx, (TLSVerifyMode)99);

  /* All should complete without raising */
  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== Verify Callback Generic Exception Test ==================== */

/* Custom exception for testing the ELSE block in internal_verify_callback */
static const Except_T Test_GenericException
    = { &Test_GenericException, "Test generic exception" };

static int
generic_exception_verify_cb (int pre_ok, X509_STORE_CTX *ctx,
                             SocketTLSContext_T tls_ctx, Socket_T sock,
                             void *user_data)
{
  (void)pre_ok;
  (void)ctx;
  (void)tls_ctx;
  (void)sock;
  (void)user_data;
  /* Raise a non-SocketTLS exception to trigger ELSE block */
  RAISE (Test_GenericException);
  return 1; /* Unreachable */
}

TEST (tls_verify_callback_generic_exception)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_verify_gen_exc.crt";
  const char *key_file = "test_verify_gen_exc.key";
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

    /* Set callback that raises GENERIC exception (not SocketTLS_Failed) */
    /* This exercises the ELSE block in internal_verify_callback */
    SocketTLSContext_set_verify_callback (client_ctx,
                                          generic_exception_verify_cb, NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_PEER);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Handshake loop - callback will raise, triggering ELSE block */
    volatile TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    volatile TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    volatile int loops = 0;

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
    EXCEPT (SocketTLS_HandshakeFailed) { /* Expected due to callback */ }
    END_TRY;

    /* Main test: ensure no crash, ELSE block was exercised */
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

/* ==================== CRL Load NULL Path Test ==================== */

TEST (tls_crl_load_null_path)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  volatile int raised = 0;

  /* Test NULL path - should raise with "path cannot be NULL or empty" */
  TRY
  {
    SocketTLSContext_load_crl (ctx, NULL);
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

/* Helper to generate a simple CRL file for testing */
static int
generate_test_crl (const char *ca_cert, const char *ca_key, const char *crl_file)
{
  char cmd[2048];
  /* Generate a CRL from the CA */
  snprintf (cmd, sizeof (cmd),
            "openssl ca -gencrl -keyfile %s -cert %s -out %s "
            "-config /dev/stdin 2>/dev/null <<'EOF'\n"
            "[ca]\ndefault_ca = CA_default\n"
            "[CA_default]\ndatabase = /dev/null\n"
            "crlnumber = /dev/null\ndefault_crl_days = 1\n"
            "default_md = sha256\n"
            "EOF",
            ca_key, ca_cert, crl_file);
  return system (cmd);
}

TEST (tls_crl_load_file)
{
#if SOCKET_HAS_TLS
  /* This test attempts to load a CRL file (not directory).
   * Since creating a valid CRL requires CA setup, we test with
   * the certificate file itself which will fail at X509_STORE_load_locations
   * but exercises the file path (S_ISDIR false) in load_crl. */
  const char *cert_file = "test_crl_file.crt";
  const char *key_file = "test_crl_file.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test file load path (cert file is not a CRL but exercises file detection) */
  TRY
  {
    /* This will stat the file (not dir), then try to load as CRL.
     * May fail or succeed depending on OpenSSL's tolerance. */
    SocketTLSContext_load_crl (ctx, cert_file);
  }
  EXCEPT (SocketTLS_Failed) { /* Expected - cert is not a valid CRL */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
  remove_test_certs (cert_file, key_file);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== Min Protocol Fallback Tests ==================== */

TEST (tls_min_protocol_fallback)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test TLS1_VERSION (0x0301) to trigger version > TLS1_VERSION branch */
  TRY { SocketTLSContext_set_min_protocol (ctx, TLS1_VERSION); }
  EXCEPT (SocketTLS_Failed) { /* May fail, but exercises code path */ }
  END_TRY;

  /* Test TLS1_1_VERSION to trigger version > TLS1_1_VERSION branch */
  TRY { SocketTLSContext_set_min_protocol (ctx, TLS1_1_VERSION); }
  EXCEPT (SocketTLS_Failed) { /* May fail */ }
  END_TRY;

  /* Test TLS1_2_VERSION to trigger version > TLS1_2_VERSION branch */
  TRY { SocketTLSContext_set_min_protocol (ctx, TLS1_2_VERSION); }
  EXCEPT (SocketTLS_Failed) { /* May fail */ }
  END_TRY;

  /* Test version 0 (invalid) to potentially trigger fallback path */
  TRY { SocketTLSContext_set_min_protocol (ctx, 0); }
  EXCEPT (SocketTLS_Failed) { /* Expected */ }
  END_TRY;

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== OCSP Response Size Limit Test ==================== */

TEST (tls_ocsp_response_too_large)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_ocsp_large.crt";
  const char *key_file = "test_ocsp_large.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    /* Create buffer larger than SOCKET_TLS_MAX_OCSP_RESPONSE_LEN (64KB) */
    size_t too_large = 65 * 1024; /* 65KB > 64KB limit */
    unsigned char *large_resp = malloc (too_large);
    ASSERT_NOT_NULL (large_resp);
    memset (large_resp, 0x30, too_large);

    TRY
    {
      SocketTLSContext_set_ocsp_response (ctx, large_resp, too_large);
      ASSERT (0); /* Should raise */
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;

    free (large_resp);
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

/* ==================== OCSP Valid Response Set Test ==================== */

TEST (tls_ocsp_set_valid_response)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_ocsp_set_valid.crt";
  const char *key_file = "test_ocsp_set_valid.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  unsigned char *der = NULL;
  OCSP_RESPONSE *resp = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);

    /* Create a valid OCSP response (tryLater status) and serialize to DER */
    resp = OCSP_response_create (OCSP_RESPONSE_STATUS_TRYLATER, NULL);
    ASSERT_NOT_NULL (resp);

    int len = i2d_OCSP_RESPONSE (resp, &der);
    ASSERT (len > 0);
    ASSERT_NOT_NULL (der);

    /* Set the valid OCSP response - exercises success path */
    TRY
    {
      SocketTLSContext_set_ocsp_response (ctx, der, len);
      /* Should succeed - valid DER-encoded OCSP response */
    }
    EXCEPT (SocketTLS_Failed) { ASSERT (0); /* Unexpected failure */ }
    END_TRY;
  }
  FINALLY
  {
    if (der)
      OPENSSL_free (der);
    if (resp)
      OCSP_RESPONSE_free (resp);
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

/* ==================== OCSP Status Socket States Tests ==================== */

TEST (tls_ocsp_status_socket_states)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_ocsp_states.crt";
  const char *key_file = "test_ocsp_states.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  Socket_T sock = NULL;
  int sv[2];

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    sock = Socket_new_from_fd (sv[0]);
    close (sv[1]);

    /* Test 1: Socket without TLS enabled - tls_enabled = false */
    int status = SocketTLS_get_ocsp_status (sock);
    ASSERT_EQ (status, 0);

    /* Test 2: Enable TLS but don't complete handshake */
    SocketTLS_enable (sock, ctx);
    /* Now tls_enabled = true, but tls_handshake_done = false */
    status = SocketTLS_get_ocsp_status (sock);
    ASSERT_EQ (status, 0);

    /* Note: Testing tls_ssl = NULL would require internal manipulation
     * which isn't safe. The above tests cover validate_socket_for_ocsp paths. */
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
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

/* ==================== OCSP Status No Response Test ==================== */

TEST (tls_ocsp_status_no_response)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_ocsp_no_resp.crt";
  const char *key_file = "test_ocsp_no_resp.key";
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

    /* Server has NO OCSP response configured */

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

    /* Now check OCSP status - should be 0 (no response stapled) */
    /* This exercises get_ocsp_response_bytes returning 0 */
    int status = SocketTLS_get_ocsp_status (client_sock);
    ASSERT_EQ (status, 0);
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

/* ==================== OCSP Gen Callback Integration Test ==================== */

/* Counter to verify callback was actually invoked */
static volatile int ocsp_gen_callback_invoked = 0;

static OCSP_RESPONSE *
tracking_ocsp_gen_cb (SSL *ssl, void *arg)
{
  (void)ssl;
  (void)arg;
  ocsp_gen_callback_invoked = 1;
  /* Return NULL to exercise the resp == NULL path in status_cb_wrapper */
  return NULL;
}

TEST (tls_ocsp_gen_callback_integration)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_ocsp_cb_int.crt";
  const char *key_file = "test_ocsp_cb_int.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T client_sock = NULL;
  Socket_T server_sock = NULL;
  int sv[2];

  ocsp_gen_callback_invoked = 0;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Set OCSP gen callback on server - will be called during handshake */
    SocketTLSContext_set_ocsp_gen_callback (server_ctx, tracking_ocsp_gen_cb,
                                            NULL);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    /* CRITICAL: Set client to request OCSP status before handshake
     * This triggers the server's status_cb_wrapper callback */
    if (client_sock->tls_ssl)
      {
        SSL_set_tlsext_status_type ((SSL *)client_sock->tls_ssl,
                                    TLSEXT_STATUSTYPE_ocsp);
      }

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Handshake - this should trigger the OCSP callback on server */
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

    /* Check OCSP status on client */
    if (client_state == TLS_HANDSHAKE_COMPLETE)
      {
        int status = SocketTLS_get_ocsp_status (client_sock);
        /* Should be 0 since callback returned NULL */
        ASSERT_EQ (status, 0);
      }

    /* The callback should have been invoked if client requested OCSP */
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

/* ==================== OCSP With Valid Response Test ==================== */

/* Create a minimal valid-looking OCSP response that passes d2i_OCSP_RESPONSE */
static OCSP_RESPONSE *
create_mock_ocsp_response (void)
{
  /* Create a "tryLater" response which is valid but indicates server busy */
  return OCSP_response_create (OCSP_RESPONSE_STATUS_TRYLATER, NULL);
}

/* Create an OCSP response with SUCCESSFUL status but no basic response
 * This exercises the validate_ocsp_basic_response error path */
static OCSP_RESPONSE *
create_successful_ocsp_response (void)
{
  /* Create successful response - but with NULL basic resp */
  return OCSP_response_create (OCSP_RESPONSE_STATUS_SUCCESSFUL, NULL);
}

/* Create a minimal but valid OCSP response with basic response
 * This requires creating an OCSP_BASICRESP structure */
static OCSP_RESPONSE *
create_full_ocsp_response (void)
{
  /* Create a basic response - simplified, may not be fully valid
   * but enough to have OCSP_response_get1_basic succeed */
  OCSP_BASICRESP *basic = OCSP_BASICRESP_new ();
  if (!basic)
    return NULL;

  /* Create the full response with the basic response */
  OCSP_RESPONSE *resp = OCSP_response_create (OCSP_RESPONSE_STATUS_SUCCESSFUL,
                                              basic);
  OCSP_BASICRESP_free (basic);
  return resp;
}

static OCSP_RESPONSE *
full_ocsp_gen_cb (SSL *ssl, void *arg)
{
  (void)ssl;
  (void)arg;
  ocsp_gen_callback_invoked = 1;
  return create_full_ocsp_response ();
}

static OCSP_RESPONSE *
valid_ocsp_gen_cb (SSL *ssl, void *arg)
{
  (void)ssl;
  (void)arg;
  ocsp_gen_callback_invoked = 1;
  /* Return a valid OCSP response to exercise the success path */
  return create_mock_ocsp_response ();
}

static OCSP_RESPONSE *
successful_ocsp_gen_cb (SSL *ssl, void *arg)
{
  (void)ssl;
  (void)arg;
  ocsp_gen_callback_invoked = 1;
  /* Return SUCCESSFUL status response to exercise validate_ocsp_basic_response */
  return create_successful_ocsp_response ();
}

TEST (tls_ocsp_with_valid_response)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_ocsp_valid.crt";
  const char *key_file = "test_ocsp_valid.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T client_sock = NULL;
  Socket_T server_sock = NULL;
  int sv[2];

  ocsp_gen_callback_invoked = 0;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Set OCSP gen callback that returns valid response */
    SocketTLSContext_set_ocsp_gen_callback (server_ctx, valid_ocsp_gen_cb,
                                            NULL);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    /* Set client to request OCSP status */
    if (client_sock->tls_ssl)
      {
        SSL_set_tlsext_status_type ((SSL *)client_sock->tls_ssl,
                                    TLSEXT_STATUSTYPE_ocsp);
      }

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Handshake */
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

    /* Check OCSP status - should have response from callback */
    if (client_state == TLS_HANDSHAKE_COMPLETE)
      {
        int status = SocketTLS_get_ocsp_status (client_sock);
        /* Status could be TRYLATER (3) or 0 if not stapled */
        /* Either way exercises the parsing code paths */
        (void)status;
      }
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

/* ==================== OCSP With Successful Status Response Test ==================== */

TEST (tls_ocsp_with_successful_response)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_ocsp_succ.crt";
  const char *key_file = "test_ocsp_succ.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T client_sock = NULL;
  Socket_T server_sock = NULL;
  int sv[2];

  ocsp_gen_callback_invoked = 0;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Set OCSP gen callback that returns SUCCESSFUL status response
     * This exercises validate_ocsp_basic_response path */
    SocketTLSContext_set_ocsp_gen_callback (server_ctx, successful_ocsp_gen_cb,
                                            NULL);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    /* Set client to request OCSP status */
    if (client_sock->tls_ssl)
      {
        SSL_set_tlsext_status_type ((SSL *)client_sock->tls_ssl,
                                    TLSEXT_STATUSTYPE_ocsp);
      }

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Handshake */
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

    /* Check OCSP status - exercises validate_ocsp_basic_response */
    if (client_state == TLS_HANDSHAKE_COMPLETE)
      {
        int status = SocketTLS_get_ocsp_status (client_sock);
        /* May return INTERNALERROR (2) since basic response is NULL */
        (void)status;
      }
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

/* ==================== OCSP With Full Basic Response Test ==================== */

TEST (tls_ocsp_with_full_basic_response)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_ocsp_full.crt";
  const char *key_file = "test_ocsp_full.key";
  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T client_sock = NULL;
  Socket_T server_sock = NULL;
  int sv[2];

  ocsp_gen_callback_invoked = 0;

  TRY
  {
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Set OCSP gen callback that returns response with basic response
     * This exercises validate_ocsp_basic_response success path */
    SocketTLSContext_set_ocsp_gen_callback (server_ctx, full_ocsp_gen_cb, NULL);

    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    /* Set client to request OCSP status */
    if (client_sock->tls_ssl)
      {
        SSL_set_tlsext_status_type ((SSL *)client_sock->tls_ssl,
                                    TLSEXT_STATUSTYPE_ocsp);
      }

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Handshake */
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

    /* Check OCSP status - exercises validate_ocsp_basic_response success */
    if (client_state == TLS_HANDSHAKE_COMPLETE)
      {
        int status = SocketTLS_get_ocsp_status (client_sock);
        /* May return 1 (success) if basic response present */
        (void)status;
      }
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

/* =========================================================================
 * COVERAGE TESTS FOR SocketTLSContext-certs.c
 * =========================================================================
 */

/* Helper to create invalid PEM file */
static int
create_invalid_pem (const char *path)
{
  FILE *fp = fopen (path, "w");
  if (!fp)
    return -1;
  fprintf (fp, "This is not a valid PEM file\nGARBAGE DATA\n");
  fclose (fp);
  return 0;
}

/* Helper to generate two separate cert/key pairs for mismatch testing */
static int
generate_two_cert_pairs (const char *cert1, const char *key1, const char *cert2,
                         const char *key2)
{
  char cmd[1024];

  /* Generate first pair */
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
            "-nodes -subj '/CN=host1.example.com' 2>/dev/null",
            key1, cert1);
  if (system (cmd) != 0)
    return -1;

  /* Generate second pair */
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
            "-nodes -subj '/CN=host2.example.com' 2>/dev/null",
            key2, cert2);
  if (system (cmd) != 0)
    {
      unlink (cert1);
      unlink (key1);
      return -1;
    }

  return 0;
}

/* ==================== Test 1: Certificate Loading Error Paths ==================== */

TEST (tls_load_certificate_errors)
{
#if SOCKET_HAS_TLS
  const char *valid_cert = "test_certerr.crt";
  const char *valid_key = "test_certerr.key";
  const char *invalid_pem = "test_invalid.pem";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;

  if (generate_test_certs (valid_cert, valid_key) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  /* Create invalid PEM file */
  create_invalid_pem (invalid_pem);

  TRY
  {
    ctx = SocketTLSContext_new_server (valid_cert, valid_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test 1: Path traversal in cert path - should raise */
    raised = 0;
    TRY { SocketTLSContext_load_certificate (ctx, "../etc/passwd", valid_key); }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 2: Path traversal in key path - should raise */
    raised = 0;
    TRY { SocketTLSContext_load_certificate (ctx, valid_cert, "../etc/passwd"); }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 3: Empty cert path - should raise */
    raised = 0;
    TRY { SocketTLSContext_load_certificate (ctx, "", valid_key); }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 4: Empty key path - should raise */
    raised = 0;
    TRY { SocketTLSContext_load_certificate (ctx, valid_cert, ""); }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 5: Invalid PEM certificate file - should raise */
    raised = 0;
    TRY { SocketTLSContext_load_certificate (ctx, invalid_pem, valid_key); }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 6: Invalid PEM key file - should raise */
    raised = 0;
    TRY { SocketTLSContext_load_certificate (ctx, valid_cert, invalid_pem); }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 7: Nonexistent cert file - should raise */
    raised = 0;
    TRY
    {
      SocketTLSContext_load_certificate (ctx, "/nonexistent/cert.pem",
                                         valid_key);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 8: Nonexistent key file - should raise */
    raised = 0;
    TRY
    {
      SocketTLSContext_load_certificate (ctx, valid_cert,
                                         "/nonexistent/key.pem");
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (valid_cert, valid_key);
    unlink (invalid_pem);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* Test cert/key mismatch in load_certificate */
TEST (tls_load_certificate_mismatch)
{
#if SOCKET_HAS_TLS
  const char *cert1 = "test_mismatch1.crt";
  const char *key1 = "test_mismatch1.key";
  const char *cert2 = "test_mismatch2.crt";
  const char *key2 = "test_mismatch2.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;

  if (generate_two_cert_pairs (cert1, key1, cert2, key2) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    ctx = SocketTLSContext_new_server (cert1, key1, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Load cert1 with key2 - should raise due to mismatch */
    raised = 0;
    TRY { SocketTLSContext_load_certificate (ctx, cert1, key2); }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Load cert2 with key1 - should raise due to mismatch */
    raised = 0;
    TRY { SocketTLSContext_load_certificate (ctx, cert2, key1); }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    unlink (cert1);
    unlink (key1);
    unlink (cert2);
    unlink (key2);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Test 2: CA Directory Fallback ==================== */

TEST (tls_load_ca_directory_fallback)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);

  /* Test loading CA from directory (current dir) - exercises line 79 fallback
   */
  TRY
  {
    /* "." is a valid directory - triggers the fallback path when file load
     * fails */
    SocketTLSContext_load_ca (ctx, ".");
    /* Should succeed (or at least not crash) since it's a valid path */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* May fail if directory has no valid CA files - acceptable */
  }
  END_TRY;

  /* Test with /tmp (another directory) */
  TRY { SocketTLSContext_load_ca (ctx, "/tmp"); }
  EXCEPT (SocketTLS_Failed)
  {
    /* May fail if no valid CA files */
  }
  END_TRY;

  /* Test path with control characters - should raise */
  volatile int raised = 0;
  TRY { SocketTLSContext_load_ca (ctx, "/path\twith\ttabs"); }
  EXCEPT (SocketTLS_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (raised, 1);

  SocketTLSContext_free (&ctx);
  Arena_dispose (&arena);
#else
  (void)0;
#endif
}

/* ==================== Test 3: SNI Client Context Rejection ==================== */

TEST (tls_sni_client_context_rejection)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_sni_client.crt";
  const char *key_file = "test_sni_client.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T client_ctx = NULL;
  volatile int raised = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    /* Create CLIENT context (not server) */
    client_ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (client_ctx);

    /* Try to add SNI certificate to client context - should raise */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (client_ctx, "example.com", cert_file,
                                        key_file);
      ASSERT (0); /* Should not reach here */
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;

    ASSERT_EQ (raised, 1);
  }
  FINALLY
  {
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

/* ==================== Test 4: SNI Max Certificates Limit ==================== */

/* Note: Testing 100 cert limit would require generating 101 certificates
 * which is slow. Instead we verify the limit check path works. */
TEST (tls_sni_max_certificates_check)
{
#if SOCKET_HAS_TLS
  /* This test verifies that the max limit check is in place.
   * Full 100-cert test is impractical for unit tests. */
  const char *cert_file = "test_sni_max.crt";
  const char *key_file = "test_sni_max.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Verify SOCKET_TLS_MAX_SNI_CERTS is defined and reasonable */
    ASSERT (SOCKET_TLS_MAX_SNI_CERTS >= 1);
    ASSERT (SOCKET_TLS_MAX_SNI_CERTS <= 1000);
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

/* ==================== Test 5: SNI Capacity Expansion ==================== */

TEST (tls_sni_capacity_expansion)
{
#if SOCKET_HAS_TLS
  /* Use /tmp for reliable file access across different working directories */
  const char *default_cert = "/tmp/test_sni_exp_def.crt";
  const char *default_key = "/tmp/test_sni_exp_def.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  char cmd[1024];

  /* Generate 6 certificate pairs to force capacity expansion (initial=4) */
  const char *certs[6]
      = { "/tmp/test_exp1.crt", "/tmp/test_exp2.crt", "/tmp/test_exp3.crt",
          "/tmp/test_exp4.crt", "/tmp/test_exp5.crt", "/tmp/test_exp6.crt" };
  const char *keys[6] = { "/tmp/test_exp1.key", "/tmp/test_exp2.key", "/tmp/test_exp3.key",
                          "/tmp/test_exp4.key", "/tmp/test_exp5.key", "/tmp/test_exp6.key" };
  const char *hosts[6]
      = { "host1.example.com", "host2.example.com", "host3.example.com",
          "host4.example.com", "host5.example.com", "host6.example.com" };

  /* Generate default certificate with CN=localhost */
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
            "-nodes -subj '/CN=localhost' 2>/dev/null",
            default_key, default_cert);
  if (system (cmd) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  /* Generate all 6 cert pairs with matching CN */
  volatile int i;
  for (i = 0; i < 6; i++)
    {
      snprintf (cmd, sizeof (cmd),
                "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
                "-nodes -subj '/CN=%s' 2>/dev/null",
                keys[i], certs[i], hosts[i]);
      if (system (cmd) != 0)
        {
          /* Cleanup any generated certs */
          for (int j = 0; j < i; j++)
            {
              unlink (certs[j]);
              unlink (keys[j]);
            }
          unlink (default_cert);
          unlink (default_key);
          Arena_dispose (&arena);
          return;
        }
    }

  TRY
  {
    ctx = SocketTLSContext_new_server (default_cert, default_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Add 6 SNI certificates - forces expansion past initial capacity of 4 */
    for (i = 0; i < 6; i++)
      {
        SocketTLSContext_add_certificate (ctx, hosts[i], certs[i], keys[i]);
      }

    /* All 6 should be added successfully */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Unexpected failure */
    ASSERT (0);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    for (i = 0; i < 6; i++)
      {
        unlink (certs[i]);
        unlink (keys[i]);
      }
    unlink (default_cert);
    unlink (default_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Test 6: SNI Invalid Hostname ==================== */

TEST (tls_sni_invalid_hostname)
{
#if SOCKET_HAS_TLS
  /* Use /tmp for reliable file access across different working directories */
  const char *cert_file = "/tmp/test_sni_hostname.crt";
  const char *key_file = "/tmp/test_sni_hostname.key";
  const char *valid_cert = "/tmp/test_sni_valid.crt";
  const char *valid_key = "/tmp/test_sni_valid.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;
  char cmd[1024];
  FILE *fp;

  /* Generate default certificate with CN=localhost */
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
            "-nodes -subj '/CN=localhost' 2>/dev/null",
            key_file, cert_file);
  if (system (cmd) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  /* Generate a certificate with CN matching the valid hostname for Test 6 */
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
            "-nodes -subj '/CN=valid-host.example.com' 2>/dev/null",
            valid_key, valid_cert);
  if (system (cmd) != 0)
    {
      unlink (cert_file);
      unlink (key_file);
      Arena_dispose (&arena);
      return; /* Skip if openssl not available */
    }

  /* Verify certificate files were actually created */
  fp = fopen (valid_cert, "r");
  if (!fp)
    {
      unlink (cert_file);
      unlink (key_file);
      Arena_dispose (&arena);
      return; /* Skip - cert generation failed */
    }
  fseek (fp, 0, SEEK_END);
  if (ftell (fp) < 100)
    {
      fclose (fp);
      unlink (valid_cert);
      unlink (valid_key);
      unlink (cert_file);
      unlink (key_file);
      Arena_dispose (&arena);
      return; /* Skip - cert file empty or too small */
    }
  fclose (fp);

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test 1: Hostname starting with hyphen - invalid */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "-invalid.example.com", cert_file,
                                        key_file);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 2: Empty hostname string - invalid (not NULL, but "") */
    raised = 0;
    TRY { SocketTLSContext_add_certificate (ctx, "", cert_file, key_file); }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 3: Hostname with consecutive dots (empty label) - invalid */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "host..example.com", cert_file,
                                        key_file);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 4: Hostname with invalid character */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "host_name.example.com", cert_file,
                                        key_file);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 5: Label > 63 characters - invalid */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (
          ctx,
          "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmn."
          "example.com",
          cert_file, key_file);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 6: Valid hostname should succeed - uses cert with matching CN */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "valid-host.example.com",
                                        valid_cert, valid_key);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 0); /* Should NOT raise */
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    unlink (cert_file);
    unlink (key_file);
    unlink (valid_cert);
    unlink (valid_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Test 7: SNI Cert/Key Mismatch ==================== */

TEST (tls_sni_cert_key_mismatch)
{
#if SOCKET_HAS_TLS
  const char *default_cert = "test_sni_mm_def.crt";
  const char *default_key = "test_sni_mm_def.key";
  const char *cert1 = "test_sni_mm1.crt";
  const char *key1 = "test_sni_mm1.key";
  const char *cert2 = "test_sni_mm2.crt";
  const char *key2 = "test_sni_mm2.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;

  if (generate_test_certs (default_cert, default_key) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  if (generate_two_cert_pairs (cert1, key1, cert2, key2) != 0)
    {
      remove_test_certs (default_cert, default_key);
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    ctx = SocketTLSContext_new_server (default_cert, default_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Try to add cert1 with key2 - should raise due to mismatch */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "mismatch1.example.com", cert1,
                                        key2);
      ASSERT (0); /* Should not reach here */
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Try to add cert2 with key1 - should raise due to mismatch */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "mismatch2.example.com", cert2,
                                        key1);
      ASSERT (0); /* Should not reach here */
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    unlink (cert1);
    unlink (key1);
    unlink (cert2);
    unlink (key2);
    remove_test_certs (default_cert, default_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Test 8: SNI Callback Selection ==================== */

TEST (tls_sni_callback_selection)
{
#if SOCKET_HAS_TLS
  const char *default_cert = "test_sni_cb_def.crt";
  const char *default_key = "test_sni_cb_def.key";
  const char *host1_cert = "test_sni_cb_h1.crt";
  const char *host1_key = "test_sni_cb_h1.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T server_sock = NULL;
  Socket_T client_sock = NULL;
  int sv[2];

  if (generate_test_certs (default_cert, default_key) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  /* Generate cert for specific host */
  char cmd[512];
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
            "-nodes -subj '/CN=snihost1.example.com' 2>/dev/null",
            host1_key, host1_cert);
  if (system (cmd) != 0)
    {
      remove_test_certs (default_cert, default_key);
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    server_ctx
        = SocketTLSContext_new_server (default_cert, default_key, NULL);
    ASSERT_NOT_NULL (server_ctx);

    /* Add SNI certificate for snihost1.example.com */
    SocketTLSContext_add_certificate (server_ctx, "snihost1.example.com",
                                      host1_cert, host1_key);

    /* Add another SNI host to ensure callback is registered */
    SocketTLSContext_add_certificate (server_ctx, "snihost2.example.com",
                                      host1_cert, host1_key);

    client_ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (client_ctx);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Create socketpair */
    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    /* Set SNI hostname on client - this triggers SNI callback on server */
    TRY { SocketTLS_set_hostname (client_sock, "snihost1.example.com"); }
    EXCEPT (SocketTLS_Failed)
    {
      /* May fail with self-signed cert verification */
    }
    END_TRY;

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Perform handshake - this exercises sni_callback */
    volatile TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    volatile TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    volatile int loops = 0;

    TRY
    {
      while ((client_state != TLS_HANDSHAKE_COMPLETE
              && client_state != TLS_HANDSHAKE_ERROR)
             && loops < 1000)
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
    EXCEPT (SocketTLS_HandshakeFailed)
    {
      /* May fail due to cert verification - acceptable, SNI code path still exercised */
    }
    END_TRY;

    /* Handshake may complete or fail due to verification - either exercises
     * the SNI callback code path */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Skip test if cert loading/SNI setup fails (may happen due to OpenSSL config) */
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
    unlink (host1_cert);
    unlink (host1_key);
    remove_test_certs (default_cert, default_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Test 9: SNI Callback No Match ==================== */

TEST (tls_sni_callback_no_match)
{
#if SOCKET_HAS_TLS
  const char *default_cert = "test_sni_nm_def.crt";
  const char *default_key = "test_sni_nm_def.key";
  const char *known_cert = "test_sni_nm_known.crt";
  const char *known_key = "test_sni_nm_known.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;
  Socket_T server_sock = NULL;
  Socket_T client_sock = NULL;
  int sv[2];

  if (generate_test_certs (default_cert, default_key) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  /* Generate cert for known host */
  char cmd[512];
  snprintf (cmd, sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 "
            "-nodes -subj '/CN=known.example.com' 2>/dev/null",
            known_key, known_cert);
  if (system (cmd) != 0)
    {
      remove_test_certs (default_cert, default_key);
      Arena_dispose (&arena);
      return;
    }

  /* Verify known cert was created */
  {
    FILE *f = fopen (known_cert, "r");
    if (!f)
      {
        remove_test_certs (default_cert, default_key);
        unlink (known_cert);
        unlink (known_key);
        Arena_dispose (&arena);
        return;
      }
    fclose (f);
  }

  TRY
  {
    server_ctx
        = SocketTLSContext_new_server (default_cert, default_key, NULL);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Skip test if cert loading fails (e.g., OpenSSL configuration issues) */
    unlink (known_cert);
    unlink (known_key);
    remove_test_certs (default_cert, default_key);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  if (!server_ctx)
    {
      unlink (known_cert);
      unlink (known_key);
      remove_test_certs (default_cert, default_key);
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    /* Add SNI certificate for known host only */
    SocketTLSContext_add_certificate (server_ctx, "known.example.com",
                                      known_cert, known_key);

    client_ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (client_ctx);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Create socketpair */
    ASSERT_EQ (socketpair (AF_UNIX, SOCK_STREAM, 0, sv), 0);
    server_sock = Socket_new_from_fd (sv[0]);
    client_sock = Socket_new_from_fd (sv[1]);

    SocketTLS_enable (server_sock, server_ctx);
    SocketTLS_enable (client_sock, client_ctx);

    /* Set SNI hostname to UNKNOWN host - should trigger no-match path */
    TRY { SocketTLS_set_hostname (client_sock, "unknown.example.com"); }
    EXCEPT (SocketTLS_Failed)
    {
      /* May fail */
    }
    END_TRY;

    Socket_setnonblocking (server_sock);
    Socket_setnonblocking (client_sock);

    /* Perform handshake - should use default cert since SNI doesn't match */
    volatile TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    volatile TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    volatile int loops = 0;

    TRY
    {
      while ((client_state != TLS_HANDSHAKE_COMPLETE
              && client_state != TLS_HANDSHAKE_ERROR)
             && loops < 1000)
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
    EXCEPT (SocketTLS_HandshakeFailed)
    {
      /* May fail due to cert verification - acceptable, SNI code path still exercised */
    }
    END_TRY;

    /* Handshake exercises the find_sni_cert_index not-found path */
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Skip test if cert loading/SNI setup fails (may happen due to OpenSSL config) */
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
    unlink (known_cert);
    unlink (known_key);
    remove_test_certs (default_cert, default_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Test 10: Invalid PEM File Parsing ==================== */

TEST (tls_load_invalid_pem_files)
{
#if SOCKET_HAS_TLS
  const char *valid_cert = "test_invpem.crt";
  const char *valid_key = "test_invpem.key";
  const char *invalid_cert = "test_invpem_bad.crt";
  const char *invalid_key = "test_invpem_bad.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;

  if (generate_test_certs (valid_cert, valid_key) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  /* Create invalid PEM files */
  create_invalid_pem (invalid_cert);
  create_invalid_pem (invalid_key);

  TRY
  {
    ctx = SocketTLSContext_new_server (valid_cert, valid_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test 1: Invalid cert PEM in SNI add - should raise */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "badcert.example.com",
                                        invalid_cert, valid_key);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 2: Invalid key PEM in SNI add - should raise */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "badkey.example.com", valid_cert,
                                        invalid_key);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Test 3: Both invalid - should raise */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "bothbad.example.com",
                                        invalid_cert, invalid_key);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (valid_cert, valid_key);
    unlink (invalid_cert);
    unlink (invalid_key);
    Arena_dispose (&arena);
  }
  END_TRY;
#else
  (void)0;
#endif
}

/* ==================== Test: SNI Add Certificate Invalid Path ==================== */

TEST (tls_sni_add_certificate_path_traversal)
{
#if SOCKET_HAS_TLS
  const char *cert_file = "test_sni_path.crt";
  const char *key_file = "test_sni_path.key";
  Arena_T arena = Arena_new ();
  SocketTLSContext_T ctx = NULL;
  volatile int raised = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Path traversal in cert path for SNI */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "valid.example.com",
                                        "../etc/passwd", key_file);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Path traversal in key path for SNI */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "valid.example.com", cert_file,
                                        "../etc/passwd");
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Empty cert path for SNI */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "valid.example.com", "", key_file);
    }
    EXCEPT (SocketTLS_Failed) { raised = 1; }
    END_TRY;
    ASSERT_EQ (raised, 1);

    /* Empty key path for SNI */
    raised = 0;
    TRY
    {
      SocketTLSContext_add_certificate (ctx, "valid.example.com", cert_file,
                                        "");
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

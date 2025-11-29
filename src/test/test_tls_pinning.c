/**
 * test_tls_pinning.c - Certificate Pinning (SPKI SHA256) Tests
 *
 * Part of the Socket Library Test Suite
 *
 * Tests:
 * 1. Pin management (add, clear, count)
 * 2. Binary and hex hash parsing
 * 3. Certificate file SPKI extraction
 * 4. Verification with matching pins
 * 5. Verification failure with enforce mode
 * 6. Warn-only mode behavior
 * 7. Multiple pins for rotation support
 * 8. Chain matching (intermediate CA)
 * 9. Edge cases and error handling
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "test/Test.h"

#ifdef SOCKET_HAS_TLS
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
            "openssl genrsa -out %s 2048 && "
            "openssl req -new -x509 -key %s -out %s -days 1 -nodes "
            "-subj '/CN=localhost' -addext \"basicConstraints = CA:TRUE\" "
            "2>/dev/null",
            key_file, key_file, cert_file);
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

/* Helper to generate known SPKI hash from certificate file */
static int
get_cert_spki_hash (const char *cert_file, unsigned char *out_hash)
{
  FILE *fp = fopen (cert_file, "r");
  if (!fp)
    return -1;

  X509 *cert = PEM_read_X509 (fp, NULL, NULL, NULL);
  fclose (fp);

  if (!cert)
    return -1;

  X509_PUBKEY *pubkey = X509_get_X509_PUBKEY (cert);
  if (!pubkey)
    {
      X509_free (cert);
      return -1;
    }

  unsigned char *spki_der = NULL;
  int spki_len = i2d_X509_PUBKEY (pubkey, &spki_der);
  if (spki_len <= 0)
    {
      X509_free (cert);
      return -1;
    }

  SHA256 (spki_der, (size_t)spki_len, out_hash);
  OPENSSL_free (spki_der);
  X509_free (cert);

  return 0;
}

/* Convert binary hash to hex string for comparison */
static void
hash_to_hex (const unsigned char *hash, char *hex_out)
{
  static const char hex_chars[] = "0123456789abcdef";
  for (int i = 0; i < 32; i++)
    {
      hex_out[i * 2] = hex_chars[(hash[i] >> 4) & 0x0F];
      hex_out[i * 2 + 1] = hex_chars[hash[i] & 0x0F];
    }
  hex_out[64] = '\0';
}

/* ==================== Basic Pin Management Tests ==================== */

TEST (pinning_context_initialization)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* Initially no pins configured */
  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 0);
  ASSERT_EQ (SocketTLSContext_has_pins (ctx), 0);

  /* Default enforcement is enabled */
  ASSERT_EQ (SocketTLSContext_get_pin_enforcement (ctx), 1);

  SocketTLSContext_free (&ctx);
  ASSERT_NULL (ctx);
}

TEST (pinning_add_binary_hash)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* Create a test hash (arbitrary values) */
  unsigned char hash[32];
  for (int i = 0; i < 32; i++)
    hash[i] = (unsigned char)i;

  SocketTLSContext_add_pin (ctx, hash);

  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 1);
  ASSERT_EQ (SocketTLSContext_has_pins (ctx), 1);

  /* Verify the pin is found */
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, hash), 1);

  /* Verify a different hash is not found */
  unsigned char other_hash[32];
  memset (other_hash, 0xFF, 32);
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, other_hash), 0);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_add_hex_hash)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* Add hex-encoded hash */
  const char *hex_hash
      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  SocketTLSContext_add_pin_hex (ctx, hex_hash);

  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 1);

  /* Convert hex to binary for verification */
  unsigned char expected[32];
  for (int i = 0; i < 32; i++)
    {
      int hi = (hex_hash[i * 2] >= 'a') ? hex_hash[i * 2] - 'a' + 10
                                        : hex_hash[i * 2] - '0';
      int lo = (hex_hash[i * 2 + 1] >= 'a') ? hex_hash[i * 2 + 1] - 'a' + 10
                                            : hex_hash[i * 2 + 1] - '0';
      expected[i] = (unsigned char)((hi << 4) | lo);
    }

  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, expected), 1);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_add_hex_with_prefix)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* Add with "sha256//" prefix (HPKP format) */
  const char *hex_hash
      = "sha256//aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
  SocketTLSContext_add_pin_hex (ctx, hex_hash);

  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 1);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_add_hex_uppercase)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* Uppercase hex should work */
  const char *hex_hash
      = "AABBCCDD00112233AABBCCDD00112233AABBCCDD00112233AABBCCDD00112233";
  SocketTLSContext_add_pin_hex (ctx, hex_hash);

  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 1);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_add_from_cert_file)
{
  const char *cert_file = "test_pin_cert.crt";
  const char *key_file = "test_pin_cert.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    return; /* Skip if openssl not available */

  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  TRY
  {
    SocketTLSContext_add_pin_from_cert (ctx, cert_file);
    ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 1);

    /* Get the actual hash and verify it matches */
    unsigned char expected_hash[32];
    if (get_cert_spki_hash (cert_file, expected_hash) == 0)
      {
        ASSERT_EQ (SocketTLSContext_verify_pin (ctx, expected_hash), 1);
      }
  }
  FINALLY
  {
    SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (pinning_clear_pins)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* Add multiple pins */
  unsigned char hash1[32], hash2[32], hash3[32];
  memset (hash1, 0x11, 32);
  memset (hash2, 0x22, 32);
  memset (hash3, 0x33, 32);

  SocketTLSContext_add_pin (ctx, hash1);
  SocketTLSContext_add_pin (ctx, hash2);
  SocketTLSContext_add_pin (ctx, hash3);

  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 3);

  /* Clear all pins */
  SocketTLSContext_clear_pins (ctx);

  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 0);
  ASSERT_EQ (SocketTLSContext_has_pins (ctx), 0);

  /* Verify pins are no longer found */
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, hash1), 0);
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, hash2), 0);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_multiple_pins)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* Add multiple pins for rotation support */
  unsigned char hash1[32], hash2[32], hash3[32];
  memset (hash1, 0xAA, 32);
  memset (hash2, 0xBB, 32);
  memset (hash3, 0xCC, 32);

  SocketTLSContext_add_pin (ctx, hash1);
  SocketTLSContext_add_pin (ctx, hash2);
  SocketTLSContext_add_pin (ctx, hash3);

  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 3);

  /* All should be found */
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, hash1), 1);
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, hash2), 1);
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, hash3), 1);

  /* Unknown hash should not be found */
  unsigned char unknown[32];
  memset (unknown, 0xDD, 32);
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, unknown), 0);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_duplicate_pin_ignored)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  unsigned char hash[32];
  memset (hash, 0xEE, 32);

  /* Add same pin multiple times */
  SocketTLSContext_add_pin (ctx, hash);
  SocketTLSContext_add_pin (ctx, hash);
  SocketTLSContext_add_pin (ctx, hash);

  /* Should only have one pin */
  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 1);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_enforcement_mode)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* Default is enforce=1 */
  ASSERT_EQ (SocketTLSContext_get_pin_enforcement (ctx), 1);

  /* Disable enforcement */
  SocketTLSContext_set_pin_enforcement (ctx, 0);
  ASSERT_EQ (SocketTLSContext_get_pin_enforcement (ctx), 0);

  /* Re-enable enforcement */
  SocketTLSContext_set_pin_enforcement (ctx, 1);
  ASSERT_EQ (SocketTLSContext_get_pin_enforcement (ctx), 1);

  SocketTLSContext_free (&ctx);
}

/* ==================== Invalid Input Tests ==================== */

TEST (pinning_invalid_hex_format)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  volatile int caught = 0;

  /* Too short */
  TRY { SocketTLSContext_add_pin_hex (ctx, "abcd"); }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  END_TRY;
  ASSERT_EQ (caught, 1);

  /* Invalid characters */
  caught = 0;
  TRY
  {
    SocketTLSContext_add_pin_hex (
        ctx, "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg");
  }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  END_TRY;
  ASSERT_EQ (caught, 1);

  /* Too long */
  caught = 0;
  TRY
  {
    SocketTLSContext_add_pin_hex (
        ctx,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00");
  }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  END_TRY;
  ASSERT_EQ (caught, 1);

  /* Should still have no pins */
  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 0);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_null_hash)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  volatile int caught = 0;

  TRY { SocketTLSContext_add_pin (ctx, NULL); }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  END_TRY;
  ASSERT_EQ (caught, 1);

  caught = 0;
  TRY { SocketTLSContext_add_pin_hex (ctx, NULL); }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  END_TRY;
  ASSERT_EQ (caught, 1);

  caught = 0;
  TRY { SocketTLSContext_add_pin_hex (ctx, ""); }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  END_TRY;
  ASSERT_EQ (caught, 1);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_invalid_cert_file)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  volatile int caught = 0;

  TRY { SocketTLSContext_add_pin_from_cert (ctx, "/nonexistent/file.pem"); }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  END_TRY;
  ASSERT_EQ (caught, 1);

  caught = 0;
  TRY { SocketTLSContext_add_pin_from_cert (ctx, NULL); }
  EXCEPT (SocketTLS_Failed) { caught = 1; }
  END_TRY;
  ASSERT_EQ (caught, 1);

  SocketTLSContext_free (&ctx);
}

/* ==================== Verification Tests ==================== */

TEST (pinning_verify_pin_null_safe)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* NULL hash should return 0 (not found) */
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, NULL), 0);

  /* NULL cert should return 0 */
  ASSERT_EQ (SocketTLSContext_verify_cert_pin (ctx, NULL), 0);

  SocketTLSContext_free (&ctx);
}

TEST (pinning_verify_cert_pin)
{
  const char *cert_file = "test_verify_pin.crt";
  const char *key_file = "test_verify_pin.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  TRY
  {
    /* Get the hash from the cert file */
    unsigned char hash[32];
    if (get_cert_spki_hash (cert_file, hash) != 0)
      {
        remove_test_certs (cert_file, key_file);
        SocketTLSContext_free (&ctx);
        return;
      }

    /* Add the pin */
    SocketTLSContext_add_pin (ctx, hash);

    /* Load the cert and verify */
    FILE *fp = fopen (cert_file, "r");
    ASSERT_NOT_NULL (fp);
    X509 *cert = PEM_read_X509 (fp, NULL, NULL, NULL);
    fclose (fp);
    ASSERT_NOT_NULL (cert);

    ASSERT_EQ (SocketTLSContext_verify_cert_pin (ctx, cert), 1);

    X509_free (cert);
  }
  FINALLY
  {
    SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

/* ==================== Live Handshake Tests ==================== */

TEST (pinning_handshake_with_correct_pin)
{
  const char *cert_file = "test_pin_hs.crt";
  const char *key_file = "test_pin_hs.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Create server context */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (server_ctx);

    /* Create client context with correct pin */
    client_ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (client_ctx);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Add the server's certificate pin */
    SocketTLSContext_add_pin_from_cert (client_ctx, cert_file);
    ASSERT_EQ (SocketTLSContext_get_pin_count (client_ctx), 1);

    /* Create socket pair */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Enable TLS */
    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Perform handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && client_state != TLS_HANDSHAKE_ERROR
           && server_state != TLS_HANDSHAKE_ERROR && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    /* Handshake should complete successfully with correct pin */
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
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

TEST (pinning_handshake_with_wrong_pin_enforce)
{
  const char *cert_file = "test_pin_wrong.crt";
  const char *key_file = "test_pin_wrong.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;
  volatile int handshake_failed = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Create server context */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (server_ctx);

    /* Create client context with WRONG pin */
    client_ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (client_ctx);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_PEER);

    /* Add a wrong pin (all zeros) */
    unsigned char wrong_pin[32];
    memset (wrong_pin, 0, 32);
    SocketTLSContext_add_pin (client_ctx, wrong_pin);
    SocketTLSContext_set_pin_enforcement (client_ctx, 1); /* Enforce mode */

    /* Create socket pair */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Enable TLS */
    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Perform handshake - should fail */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            && client_state != TLS_HANDSHAKE_ERROR)
           || (server_state != TLS_HANDSHAKE_COMPLETE
               && server_state != TLS_HANDSHAKE_ERROR))
      {
        TRY
        {
          if (client_state != TLS_HANDSHAKE_COMPLETE
              && client_state != TLS_HANDSHAKE_ERROR)
            client_state = SocketTLS_handshake (client);
        }
        EXCEPT (SocketTLS_HandshakeFailed)
        {
          client_state = TLS_HANDSHAKE_ERROR;
          handshake_failed = 1;
        }
        END_TRY;

        TRY
        {
          if (server_state != TLS_HANDSHAKE_COMPLETE
              && server_state != TLS_HANDSHAKE_ERROR)
            server_state = SocketTLS_handshake (server);
        }
        EXCEPT (SocketTLS_HandshakeFailed) { server_state = TLS_HANDSHAKE_ERROR; }
        END_TRY;

        loops++;
        if (loops > 1000)
          break;
        usleep (1000);
      }

    /* Client should fail due to pin mismatch */
    ASSERT (client_state == TLS_HANDSHAKE_ERROR || handshake_failed);
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

TEST (pinning_handshake_warn_only_mode)
{
  const char *cert_file = "test_pin_warn.crt";
  const char *key_file = "test_pin_warn.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Create server context */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (server_ctx);

    /* Create client context with wrong pin but warn-only mode */
    client_ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (client_ctx);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Add a wrong pin */
    unsigned char wrong_pin[32];
    memset (wrong_pin, 0xFF, 32);
    SocketTLSContext_add_pin (client_ctx, wrong_pin);
    SocketTLSContext_set_pin_enforcement (client_ctx, 0); /* Warn only */

    /* Create socket pair */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Enable TLS */
    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Perform handshake - should succeed in warn-only mode */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;

    while ((client_state != TLS_HANDSHAKE_COMPLETE
            || server_state != TLS_HANDSHAKE_COMPLETE)
           && client_state != TLS_HANDSHAKE_ERROR
           && server_state != TLS_HANDSHAKE_ERROR && loops < 1000)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        loops++;
        usleep (1000);
      }

    /* Should succeed in warn-only mode even with wrong pin */
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
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;
}

/* ==================== Binary Search Tests ==================== */

TEST (pinning_binary_search_correctness)
{
  SocketTLSContext_T ctx = SocketTLSContext_new_client (NULL);
  ASSERT_NOT_NULL (ctx);

  /* Add pins in non-sorted order to verify sorting */
  unsigned char hashes[10][32];
  for (int i = 0; i < 10; i++)
    {
      memset (hashes[i], (unsigned char)(i * 17), 32); /* Non-sequential values */
    }

  /* Add in random order */
  SocketTLSContext_add_pin (ctx, hashes[5]);
  SocketTLSContext_add_pin (ctx, hashes[2]);
  SocketTLSContext_add_pin (ctx, hashes[8]);
  SocketTLSContext_add_pin (ctx, hashes[1]);
  SocketTLSContext_add_pin (ctx, hashes[9]);
  SocketTLSContext_add_pin (ctx, hashes[3]);
  SocketTLSContext_add_pin (ctx, hashes[7]);
  SocketTLSContext_add_pin (ctx, hashes[0]);
  SocketTLSContext_add_pin (ctx, hashes[6]);
  SocketTLSContext_add_pin (ctx, hashes[4]);

  ASSERT_EQ (SocketTLSContext_get_pin_count (ctx), 10);

  /* All should be findable */
  for (int i = 0; i < 10; i++)
    {
      ASSERT (SocketTLSContext_verify_pin (ctx, hashes[i]) == 1);
    }

  /* Non-existent should not be found */
  unsigned char missing[32];
  memset (missing, 0xFE, 32);
  ASSERT_EQ (SocketTLSContext_verify_pin (ctx, missing), 0);

  SocketTLSContext_free (&ctx);
}

/* ==================== Server Context Tests ==================== */

TEST (pinning_on_server_context)
{
  const char *cert_file = "test_srv_pin.crt";
  const char *key_file = "test_srv_pin.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Server contexts can also have pins (for client cert pinning) */
    SocketTLSContext_T server_ctx
        = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (server_ctx);

    unsigned char hash[32];
    memset (hash, 0x42, 32);
    SocketTLSContext_add_pin (server_ctx, hash);

    ASSERT_EQ (SocketTLSContext_get_pin_count (server_ctx), 1);

    SocketTLSContext_free (&server_ctx);
  }
  FINALLY { remove_test_certs (cert_file, key_file); }
  END_TRY;
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}


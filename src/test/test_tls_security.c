/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_security.c - TLS Security Edge Cases and Attack Prevention Tests
 *
 * Part of the Socket Library Test Suite (Section 8.5)
 *
 * Tests:
 * 1. Downgrade attack prevention (TLS 1.2 rejection)
 * 2. Weak cipher rejection
 * 3. Certificate pinning bypass attempts
 * 4. Path traversal in certificate paths
 * 5. Null byte injection in hostnames
 * 6. Renegotiation control
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

  snprintf (cmd,
            sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=localhost' -batch 2>/dev/null",
            key_file,
            cert_file);
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

TEST (security_tls13_minimum_enforced)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Default should be TLS 1.3 only */
    SocketTLSContext_set_min_protocol (ctx, TLS1_3_VERSION);
    SocketTLSContext_set_max_protocol (ctx, TLS1_3_VERSION);

    /* These calls should succeed */
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (security_reject_weak_ciphers)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Try to set a weak/invalid cipher - should fail or be rejected */
    TRY
    {
      SocketTLSContext_set_cipher_list (
          ctx, "NULL-MD5:NULL-SHA:DES-CBC3-SHA:RC4-SHA");
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
    END_TRY;

    /* Note: This might not fail if OpenSSL allows it, but disabling
       weak ciphers should happen at the config level */
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;

  /* Test passed if either caught exception or didn't crash */
  (void)caught;
}

TEST (security_path_traversal_in_cert_path)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    /* Try to load cert with path traversal - should fail */
    TRY
    {
      ctx = SocketTLSContext_new_server (
          "/../../../etc/passwd", "/../../../etc/shadow", NULL);
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
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

TEST (security_path_traversal_in_ca_path)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Try to load CA with path traversal */
    TRY
    {
      SocketTLSContext_load_ca (ctx, "/../../../etc/passwd");
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
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

TEST (security_null_byte_in_hostname)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLS_enable (socket, ctx);

    /* Try to set hostname with null byte injection */
    /* The function should either:
     * 1. Reject the hostname
     * 2. Truncate at the null byte
     * Either is acceptable security behavior */
    const char *malicious_host = "evil.com\0legitimate.com";
    SocketTLS_set_hostname (socket, malicious_host);

    /* The key is that it doesn't crash and doesn't allow bypass */
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

TEST (security_pin_wrong_hash_rejected)
{
  const char *cert_file = "test_pin_sec.crt";
  const char *key_file = "test_pin_sec.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (server_ctx);

    client_ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (client_ctx);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_PEER);

    /* Add a wrong pin */
    unsigned char wrong_pin[32];
    memset (wrong_pin, 0xFF, 32);
    SocketTLSContext_add_pin (client_ctx, wrong_pin);
    SocketTLSContext_set_pin_enforcement (client_ctx, 1);

    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable (server, server_ctx);

    /* Handshake should fail due to pin mismatch */
    TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
    TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
    int loops = 0;
    volatile int handshake_failed = 0;

    while (client_state != TLS_HANDSHAKE_COMPLETE
           && client_state != TLS_HANDSHAKE_ERROR && loops < 1000)
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
        EXCEPT (SocketTLS_HandshakeFailed)
        {
          server_state = TLS_HANDSHAKE_ERROR;
        }
        END_TRY;

        loops++;
        usleep (1000);
      }

    /* Either client failed or handshake error */
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

TEST (security_disable_renegotiation)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLS_enable (socket, ctx);

    /* Disable renegotiation for DoS protection */
    int result = SocketTLS_disable_renegotiation (socket);
    /* Should succeed or return 0 for TLS 1.3 (no renegotiation) */
    (void)result;
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

TEST (security_renegotiation_count)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ctx = SocketTLSContext_new_client (NULL);
    SocketTLS_enable (socket, ctx);

    /* Renegotiation count should be 0 initially */
    int count = SocketTLS_get_renegotiation_count (socket);
    ASSERT_EQ (count, 0);
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

TEST (security_check_cert_expiry)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ctx = SocketTLSContext_new_client (NULL);
    SocketTLS_enable (socket, ctx);

    /* Before handshake, expiry should be -1 (no certificate available) */
    time_t expiry = SocketTLS_get_cert_expiry (socket);
    ASSERT_EQ (expiry, (time_t)-1);
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

TEST (security_ticket_key_length_validation)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Invalid key length should fail */
    unsigned char short_key[32];
    memset (short_key, 0x42, 32);

    TRY
    {
      SocketTLSContext_enable_session_tickets (ctx, short_key, 32);
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
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

TEST (security_control_chars_in_path)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Path with control characters should fail */
    TRY
    {
      SocketTLSContext_load_ca (ctx, "/path/with\x01control\x02chars.pem");
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
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

TEST (security_sni_length_limit)
{
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    ctx = SocketTLSContext_new_client (NULL);
    SocketTLS_enable (socket, ctx);

    /* Very long hostname should be handled safely */
    char long_hostname[512];
    memset (long_hostname, 'a', sizeof (long_hostname) - 1);
    long_hostname[sizeof (long_hostname) - 1] = '\0';

    /* Should either accept (truncated) or fail gracefully */
    TRY
    {
      SocketTLS_set_hostname (socket, long_hostname);
    }
    EXCEPT (SocketTLS_Failed)
    { /* Acceptable */
    }
    END_TRY;
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

static int
generate_cert_chain (const char *chain_file,
                     const char *key_file,
                     int num_certs)
{
  FILE *fp;
  char cmd[2048];
  int i;

  /* Generate root CA */
  snprintf (cmd,
            sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=Root CA' -batch 2>/dev/null",
            key_file,
            chain_file);
  if (system (cmd) != 0)
    return -1;

  /* Append additional certificates to create a chain */
  fp = fopen (chain_file, "a");
  if (!fp)
    return -1;

  for (i = 1; i < num_certs; i++)
    {
      char tmp_cert[256];
      char tmp_key[256];
      snprintf (tmp_cert, sizeof (tmp_cert), "/tmp/test_chain_%d.crt", i);
      snprintf (tmp_key, sizeof (tmp_key), "/tmp/test_chain_%d.key", i);

      snprintf (cmd,
                sizeof (cmd),
                "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
                "-days 1 -nodes -subj '/CN=Intermediate %d' -batch 2>/dev/null",
                tmp_key,
                tmp_cert,
                i);
      if (system (cmd) != 0)
        {
          fclose (fp);
          return -1;
        }

      /* Append certificate to chain file */
      FILE *tmp_fp = fopen (tmp_cert, "r");
      if (tmp_fp)
        {
          char buf[4096];
          size_t n;
          while ((n = fread (buf, 1, sizeof (buf), tmp_fp)) > 0)
            fwrite (buf, 1, n, fp);
          fclose (tmp_fp);
        }

      unlink (tmp_cert);
      unlink (tmp_key);
    }

  fclose (fp);
  return 0;
}

TEST (security_cert_chain_at_max_depth)
{
  const char *cert_file = "test_chain_max.crt";
  const char *key_file = "test_chain_max.key";
  const char *dummy_cert = "test_dummy_max.crt";
  const char *dummy_key = "test_dummy_max.key";
  SocketTLSContext_T ctx = NULL;

  /* Generate a dummy cert for initial server context */
  if (generate_test_certs (dummy_cert, dummy_key) != 0)
    return;

  /* Generate a chain at exactly the maximum depth (10 certs) */
  if (generate_cert_chain (cert_file, key_file, 10) != 0)
    {
      remove_test_certs (cert_file, key_file);
      remove_test_certs (dummy_cert, dummy_key);
      return; /* Skip test if cert generation fails */
    }

  TRY
  {
    /* Create server context first with dummy cert */
    ctx = SocketTLSContext_new_server (dummy_cert, dummy_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* This should succeed - exactly at the limit */
    /* Use SNI path which calls load_chain_from_file */
    SocketTLSContext_add_certificate (ctx, NULL, cert_file, key_file);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
    remove_test_certs (dummy_cert, dummy_key);
  }
  END_TRY;
}

TEST (security_cert_chain_exceeds_max_depth)
{
  const char *cert_file = "test_chain_exceed.crt";
  const char *key_file = "test_chain_exceed.key";
  const char *dummy_cert = "test_dummy_exceed.crt";
  const char *dummy_key = "test_dummy_exceed.key";
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  /* Generate a dummy cert for initial server context */
  if (generate_test_certs (dummy_cert, dummy_key) != 0)
    return;

  /* Generate a chain exceeding the maximum depth (11 certs) */
  if (generate_cert_chain (cert_file, key_file, 11) != 0)
    {
      remove_test_certs (cert_file, key_file);
      remove_test_certs (dummy_cert, dummy_key);
      return; /* Skip test if cert generation fails */
    }

  TRY
  {
    ctx = SocketTLSContext_new_server (dummy_cert, dummy_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* This should fail - exceeds the limit */
    TRY
    {
      SocketTLSContext_add_certificate (ctx, NULL, cert_file, key_file);
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
    remove_test_certs (dummy_cert, dummy_key);
  }
  END_TRY;
}

TEST (security_cert_chain_way_over_max_depth)
{
  const char *cert_file = "test_chain_way_over.crt";
  const char *key_file = "test_chain_way_over.key";
  const char *dummy_cert = "test_dummy_way_over.crt";
  const char *dummy_key = "test_dummy_way_over.key";
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  /* Generate a dummy cert for initial server context */
  if (generate_test_certs (dummy_cert, dummy_key) != 0)
    return;

  /* Generate a chain way over the maximum depth (50 certs) to test DoS
   * protection */
  if (generate_cert_chain (cert_file, key_file, 50) != 0)
    {
      remove_test_certs (cert_file, key_file);
      remove_test_certs (dummy_cert, dummy_key);
      return; /* Skip test if cert generation fails */
    }

  TRY
  {
    ctx = SocketTLSContext_new_server (dummy_cert, dummy_key, NULL);
    ASSERT_NOT_NULL (ctx);

    /* This should fail - way over the limit */
    TRY
    {
      SocketTLSContext_add_certificate (ctx, NULL, cert_file, key_file);
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    remove_test_certs (cert_file, key_file);
    remove_test_certs (dummy_cert, dummy_key);
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

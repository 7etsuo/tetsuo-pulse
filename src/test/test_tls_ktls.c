/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_ktls.c - Unit tests for kTLS (Kernel TLS) offload support
 *
 * Tests:
 * 1. kTLS availability detection
 * 2. kTLS enable/disable
 * 3. kTLS status queries before/after handshake
 * 4. Graceful fallback when kTLS unavailable
 * 5. SocketTLS_sendfile operations
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
#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"
#include <openssl/crypto.h>

/* ==================== Test Helpers ==================== */

/**
 * Helper to generate temporary self-signed certificate
 */
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

/* ==================== kTLS Availability Tests ==================== */

TEST (ktls_availability_detection)
{
  /* SocketTLS_ktls_available() should return 0 or 1 without crashing */
  int available = SocketTLS_ktls_available ();

  /* Result should be boolean */
  ASSERT (available == 0 || available == 1);

  printf ("  kTLS availability: %s\n", available ? "YES" : "NO");

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(OPENSSL_NO_KTLS)
  printf ("  OpenSSL kTLS compile-time support: YES\n");
#else
  printf ("  OpenSSL kTLS compile-time support: NO\n");
  /* If OpenSSL doesn't have kTLS, availability should be 0 */
  ASSERT_EQ (available, 0);
#endif
}

/* ==================== kTLS Enable/Disable Tests ==================== */

TEST (ktls_enable_before_tls)
{
  const char *cert_file = "test_ktls_enable.crt";
  const char *key_file = "test_ktls_enable.key";
  Socket_T sock = NULL;
  SocketTLSContext_T ctx = NULL;
  volatile int exception_raised = 0;

  if (generate_test_certs (cert_file, key_file) != 0)
    return; /* Skip if openssl not available */

  TRY
  {
    /* Create a socket pair for testing */
    Socket_T client = NULL, server = NULL;
    SocketPair_new (SOCK_STREAM, &client, &server);

    /* Create TLS context */
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    ASSERT_NOT_NULL (ctx);

    /* Enable TLS on server socket */
    SocketTLS_enable (server, ctx);

    /* Enable kTLS - should succeed (sets flag) */
    SocketTLS_enable_ktls (server);

    /* Verify kTLS was requested */
    /* Note: We can't directly check the flag, but the function shouldn't raise
     */

    /* Status queries before handshake should return -1 */
    int tx_active = SocketTLS_is_ktls_tx_active (server);
    int rx_active = SocketTLS_is_ktls_rx_active (server);
    ASSERT_EQ (tx_active, -1); /* Handshake not complete */
    ASSERT_EQ (rx_active, -1);

    Socket_free (&client);
    Socket_free (&server);
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

  ASSERT_EQ (exception_raised, 0);
  ASSERT_EQ (Socket_debug_live_count (), 0);
}

TEST (ktls_enable_requires_tls)
{
  Socket_T sock = NULL;
  volatile int exception_raised = 0;

  TRY
  {
    /* Create a plain socket (no TLS) */
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    /* Try to enable kTLS without TLS - should raise exception */
    SocketTLS_enable_ktls (sock);

    /* Should not reach here */
    ASSERT (0);
  }
  EXCEPT (SocketTLS_Failed)
  {
    exception_raised = 1;
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;

  ASSERT_EQ (exception_raised, 1);
  ASSERT_EQ (Socket_debug_live_count (), 0);
}

/* ==================== kTLS Status Query Tests ==================== */

TEST (ktls_status_invalid_socket)
{
  /* NULL socket should return -1 */
  ASSERT_EQ (SocketTLS_is_ktls_tx_active (NULL), -1);
  ASSERT_EQ (SocketTLS_is_ktls_rx_active (NULL), -1);
}

TEST (ktls_status_no_tls)
{
  Socket_T sock = NULL;

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    /* Non-TLS socket should return -1 */
    ASSERT_EQ (SocketTLS_is_ktls_tx_active (sock), -1);
    ASSERT_EQ (SocketTLS_is_ktls_rx_active (sock), -1);
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;

  ASSERT_EQ (Socket_debug_live_count (), 0);
}

/* ==================== kTLS Full Handshake Test ==================== */

TEST (ktls_full_handshake)
{
  const char *cert_file = "test_ktls_handshake.crt";
  const char *key_file = "test_ktls_handshake.key";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  TRY
  {
    /* Create socket pair */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Create contexts */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    /* Enable TLS on both */
    SocketTLS_enable (server, server_ctx);
    SocketTLS_enable (client, client_ctx);

    /* Enable kTLS on both */
    SocketTLS_enable_ktls (server);
    SocketTLS_enable_ktls (client);

    /* Drive handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_NOT_STARTED;
    TLSHandshakeState server_state = TLS_HANDSHAKE_NOT_STARTED;
    int max_iterations = 100;

    while (max_iterations-- > 0)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);

        if (client_state == TLS_HANDSHAKE_COMPLETE
            && server_state == TLS_HANDSHAKE_COMPLETE)
          break;

        usleep (1000);
      }

    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Check kTLS status after handshake */
    int client_tx = SocketTLS_is_ktls_tx_active (client);
    int client_rx = SocketTLS_is_ktls_rx_active (client);
    int server_tx = SocketTLS_is_ktls_tx_active (server);
    int server_rx = SocketTLS_is_ktls_rx_active (server);

    /* Status should be 0 or 1 (not -1) after successful handshake */
    ASSERT (client_tx == 0 || client_tx == 1);
    ASSERT (client_rx == 0 || client_rx == 1);
    ASSERT (server_tx == 0 || server_tx == 1);
    ASSERT (server_rx == 0 || server_rx == 1);

    printf ("  kTLS client TX: %d, RX: %d\n", client_tx, client_rx);
    printf ("  kTLS server TX: %d, RX: %d\n", server_tx, server_rx);

    /* Test I/O still works (regardless of kTLS status) */
    const char *test_msg = "Hello kTLS!";
    ssize_t sent = SocketTLS_send (client, test_msg, strlen (test_msg));
    ASSERT (sent > 0);

    char buf[64];
    ssize_t received = 0;
    for (int i = 0; i < 10 && received <= 0; i++)
      {
        received = SocketTLS_recv (server, buf, sizeof (buf) - 1);
        if (received == 0 && errno == EAGAIN)
          usleep (1000);
      }
    ASSERT (received > 0);
    buf[received] = '\0';
    ASSERT (strcmp (buf, test_msg) == 0);
  }
  FINALLY
  {
    if (client)
      {
        /* Use SocketTLS_disable for best-effort cleanup without exceptions.
         * SocketTLS_shutdown can timeout and raise exceptions which would
         * prevent subsequent cleanup in the FINALLY block. */
        SocketTLS_disable (client);
        Socket_free (&client);
      }
    if (server)
      {
        SocketTLS_disable (server);
        Socket_free (&server);
      }
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;

  ASSERT_EQ (Socket_debug_live_count (), 0);
}

/* ==================== kTLS Sendfile Test ==================== */

TEST (ktls_sendfile_basic)
{
  const char *cert_file = "test_ktls_sendfile.crt";
  const char *key_file = "test_ktls_sendfile.key";
  const char *test_file = "/tmp/ktls_test_data.bin";
  const char *file_content = "This is test data for kTLS sendfile.";
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;
  volatile int file_fd = -1;

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  /* Create test file */
  {
    int fd = open (test_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
      {
        remove_test_certs (cert_file, key_file);
        return;
      }
    ssize_t written = write (fd, file_content, strlen (file_content));
    (void)written;
    close (fd);
  }

  TRY
  {
    /* Create socket pair */
    SocketPair_new (SOCK_STREAM, &client, &server);
    Socket_setnonblocking (client);
    Socket_setnonblocking (server);

    /* Setup TLS */
    server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
    client_ctx = SocketTLSContext_new_client (NULL);
    SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);

    SocketTLS_enable (server, server_ctx);
    SocketTLS_enable (client, client_ctx);
    SocketTLS_enable_ktls (server);
    SocketTLS_enable_ktls (client);

    /* Complete handshake */
    TLSHandshakeState client_state = TLS_HANDSHAKE_NOT_STARTED;
    TLSHandshakeState server_state = TLS_HANDSHAKE_NOT_STARTED;
    for (int i = 0; i < 100; i++)
      {
        if (client_state != TLS_HANDSHAKE_COMPLETE)
          client_state = SocketTLS_handshake (client);
        if (server_state != TLS_HANDSHAKE_COMPLETE)
          server_state = SocketTLS_handshake (server);
        if (client_state == TLS_HANDSHAKE_COMPLETE
            && server_state == TLS_HANDSHAKE_COMPLETE)
          break;
        usleep (1000);
      }
    ASSERT_EQ (client_state, TLS_HANDSHAKE_COMPLETE);
    ASSERT_EQ (server_state, TLS_HANDSHAKE_COMPLETE);

    /* Open file for reading */
    file_fd = open (test_file, O_RDONLY);
    ASSERT (file_fd >= 0);

    /* Send file via SocketTLS_sendfile */
    ssize_t sent = SocketTLS_sendfile (client, file_fd, 0,
                                       strlen (file_content));
    ASSERT (sent > 0);
    ASSERT_EQ ((size_t)sent, strlen (file_content));

    /* Receive on server */
    char buf[256];
    ssize_t total_received = 0;
    for (int i = 0; i < 20 && (size_t)total_received < strlen (file_content);
         i++)
      {
        ssize_t n = SocketTLS_recv (server, buf + total_received,
                                    sizeof (buf) - 1 - total_received);
        if (n > 0)
          total_received += n;
        else if (n == 0 && errno == EAGAIN)
          usleep (1000);
      }
    ASSERT_EQ ((size_t)total_received, strlen (file_content));
    buf[total_received] = '\0';
    ASSERT (strcmp (buf, file_content) == 0);
  }
  FINALLY
  {
    if (file_fd >= 0)
      close (file_fd);
    if (client)
      {
        /* Use SocketTLS_disable for best-effort cleanup without exceptions */
        SocketTLS_disable (client);
        Socket_free (&client);
      }
    if (server)
      {
        SocketTLS_disable (server);
        Socket_free (&server);
      }
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    unlink (test_file);
    remove_test_certs (cert_file, key_file);
  }
  END_TRY;

  ASSERT_EQ (Socket_debug_live_count (), 0);
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  Test_run_all ();

#if SOCKET_HAS_TLS
  /* Clean up OpenSSL global state to prevent false leak reports */
  OPENSSL_cleanup ();
#endif

  return Test_get_failures () > 0 ? 1 : 0;
}

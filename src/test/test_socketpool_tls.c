/**
 * test_socketpool_tls.c - Unit tests for SocketPool TLS integration
 * Verifies that TLS fields in Connection structure are properly managed.
 */

#include "core/Arena.h"
#include "pool/SocketPool.h"
#include "test/Test.h"
/* Access internal structure to verify fields */
#include "pool/SocketPool-private.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include <time.h>

#if SOCKET_HAS_TLS
#include <openssl/ssl.h>
#endif

TEST (socketpool_tls_fields_initialization)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  /* Add socket to pool */
  Connection_T conn = SocketPool_add (pool, socket);
  ASSERT_NOT_NULL (conn);

  /* Check TLS fields initialized to zero/NULL */
  ASSERT_NULL (conn->tls_ctx);
  ASSERT_EQ (conn->tls_handshake_complete, 0);

  /* Simulate setting them */
  conn->tls_handshake_complete = 1;

  /* Verify */
  ASSERT_EQ (conn->tls_handshake_complete, 1);

  /* Remove from pool (should reset) */
  SocketPool_remove (pool, socket);

  /* Add a new socket - should get a clean slot */
  Socket_T socket2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Connection_T conn2 = SocketPool_add (pool, socket2);
  ASSERT_NOT_NULL (conn2);

  /* Should be clean (initialized) */
  ASSERT_NULL (conn2->tls_ctx);
  ASSERT_NULL (conn2->tls_session);
  ASSERT_EQ (conn2->tls_handshake_complete, 0);

  /* Cleanup */
  Socket_free (&socket);
  Socket_free (&socket2);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
#else
  /* Pass if TLS not enabled */
  ASSERT (1);
#endif
}

TEST (socketpool_tls_session_persistence)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketPool_T pool
      = SocketPool_new (arena, 1, 1024); /* Small to reuse slot */
  Socket_T socket1 = Socket_new (AF_INET, SOCK_STREAM, 0);

  /* Mock TLS enabled and session */
  SSL_CTX *ctx1 = SSL_CTX_new (TLS_method ());
  ASSERT_NOT_NULL (ctx1);
  SSL *ssl1 = SSL_new (ctx1);
  ASSERT_NOT_NULL (ssl1);
  socket1->tls_enabled = 1;
  socket1->tls_ctx = (void *)ctx1;
  socket1->tls_ssl = (void *)ssl1;

  /* Add to pool */
  Connection_T conn1 = SocketPool_add (pool, socket1);
  ASSERT_NOT_NULL (conn1);

  /* Mock save session in conn (as done in remove) */
  time_t now = time (NULL);
  SSL_SESSION *mock_session = SSL_SESSION_new ();
  ASSERT_NOT_NULL (mock_session);
  /* Suppress deprecated warnings for SSL_SESSION_set_time/set_timeout (OpenSSL 3.4+) */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
  SSL_SESSION_set_time (mock_session, now - 100L);
  SSL_SESSION_set_timeout (mock_session, 3600L);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
  conn1->tls_session = mock_session;

  /* Remove - saves session (already in code) */
  SocketPool_remove (pool, socket1);

  /* Reset happens, but tls_session kept for reuse */
  ASSERT_NOT_NULL (conn1->tls_session);
  ASSERT_EQ (conn1->tls_session, mock_session);

  /* Validate called in get/add - assume valid, not freed */

  /* Re-add same socket1 to test persistence on reuse (same endpoint) */
  Connection_T conn2 = SocketPool_add (pool, socket1);
  ASSERT_NOT_NULL (conn2);
  ASSERT_EQ (conn1, conn2); /* Same slot reused */
  ASSERT_NOT_NULL (conn2->tls_session);
  ASSERT_EQ (conn2->tls_session, mock_session); /* Persisted across remove/add */

  /* Test new socket in same slot clears old session (security) */
  Socket_T socket2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  SocketPool_remove (pool, socket1); /* Free slot again */
  /* Mock new TLS for socket2 */
  SSL_CTX *ctx2 = SSL_CTX_new (TLS_method ());
  ASSERT_NOT_NULL (ctx2);
  SSL *ssl2 = SSL_new (ctx2);
  ASSERT_NOT_NULL (ssl2);
  socket2->tls_enabled = 1;
  socket2->tls_ctx = (void *)ctx2;
  socket2->tls_ssl = (void *)ssl2;
  Connection_T conn3 = SocketPool_add (pool, socket2);
  ASSERT_NOT_NULL (conn3);
  ASSERT_EQ (conn3, conn1); /* Same slot */
  ASSERT_NULL (conn3->tls_session); /* Cleared for new socket/endpoint */

  /* Cleanup */
  Socket_free (&socket1); /* frees ssl1 */
  Socket_free (&socket2); /* frees ssl2 */
  /* Free ctx not owned by socket */
  SSL_CTX_free (ctx1);
  SSL_CTX_free (ctx2);
  /* Pool frees any remaining */
  SocketPool_free (&pool);
  Arena_dispose (&arena);
#else
  ASSERT (1);
#endif
}

TEST (socketpool_tls_session_validation)
{
#if SOCKET_HAS_TLS
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 1, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  socket->tls_enabled = 1;

  Connection_T conn = SocketPool_add (pool, socket);
  ASSERT_NOT_NULL (conn);

  /* Mock expired session */
  SSL_CTX *mock_ctx = SSL_CTX_new (TLS_method ());
  ASSERT_NOT_NULL (mock_ctx);
  SSL_SESSION *mock_session = SSL_SESSION_new ();
  ASSERT_NOT_NULL (mock_session);
  /* Suppress deprecated warnings for SSL_SESSION_set_time/set_timeout (OpenSSL 3.4+) */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
  SSL_SESSION_set_time (mock_session, 0L);
  SSL_SESSION_set_timeout (mock_session, 1L);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
  conn->tls_session = mock_session;
  SSL_CTX_free (mock_ctx);

  /* Call validate directly (internal) */
  validate_saved_session (conn, time (NULL));
  /* Expired session should be freed */
  ASSERT_NULL (conn->tls_session);

  /* Get validates too */
  Connection_T got = SocketPool_get (pool, socket);
  ASSERT_NOT_NULL (got);
  /* Assume validated */

  SocketPool_free (&pool);
  Socket_free (&socket);
  Arena_dispose (&arena);
#else
  ASSERT (1);
#endif
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

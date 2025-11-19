/**
 * test_socketpool_tls.c - Unit tests for SocketPool TLS integration
 * Verifies that TLS fields in Connection structure are properly managed.
 */

#include "test/Test.h"
#include "core/Arena.h"
#include "pool/SocketPool.h"
/* Access internal structure to verify fields */
#include "pool/SocketPool-private.h"
#include "socket/Socket.h"

TEST(socketpool_tls_fields_initialization)
{
#ifdef SOCKET_HAS_TLS
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 10, 1024);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    /* Add socket to pool */
    Connection_T conn = SocketPool_add(pool, socket);
    ASSERT_NOT_NULL(conn);

    /* Check TLS fields initialized to zero/NULL */
    ASSERT_NULL(conn->tls_ctx);
    ASSERT_EQ(conn->tls_handshake_complete, 0);

    /* Simulate setting them */
    conn->tls_handshake_complete = 1;
    
    /* Verify */
    ASSERT_EQ(conn->tls_handshake_complete, 1);

    /* Remove from pool (should reset) */
    SocketPool_remove(pool, socket);
    
    /* Add a new socket - should get a clean slot */
    Socket_T socket2 = Socket_new(AF_INET, SOCK_STREAM, 0);
    Connection_T conn2 = SocketPool_add(pool, socket2);
    ASSERT_NOT_NULL(conn2);
    
    /* Should be clean (initialized) */
    ASSERT_NULL(conn2->tls_ctx);
    ASSERT_EQ(conn2->tls_handshake_complete, 0);

    /* Cleanup */
    Socket_free(&socket);
    Socket_free(&socket2);
    SocketPool_free(&pool);
    Arena_dispose(&arena);
#else
    /* Pass if TLS not enabled */
    ASSERT(1);
#endif
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}

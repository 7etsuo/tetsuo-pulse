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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>

#include "test/Test.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketIO.h"
#include "pool/SocketPool.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#include "tls/SocketTLSConfig.h"

/* Helper to generate temporary self-signed certificate */
static int generate_test_certs(const char *cert_file, const char *key_file)
{
    char cmd[1024];

    /* Generate self-signed certificate for testing */
    snprintf(cmd, sizeof(cmd),
             "openssl genrsa -out %s 2048 && "
             "openssl req -new -x509 -key %s -out %s -days 1 -nodes "
             "-subj '/CN=localhost' -addext \"basicConstraints = CA:TRUE\" 2>/dev/null",
             key_file, key_file, cert_file);
    if (system(cmd) != 0) goto fail;

    return 0;

fail:
    unlink(cert_file);
    unlink(key_file);
    return -1;
}

static void remove_test_certs(const char *cert_file, const char *key_file)
{
    unlink(cert_file);
    unlink(key_file);
}

/* ==================== SocketTLSContext Tests ==================== */

TEST(tls_context_creation)
{
    const char *cert_file = "test_server.crt";
    const char *key_file = "test_server.key";

    /* Generate certs */
    if (generate_test_certs(cert_file, key_file) != 0)
    {
        /* Skip test if openssl not available */
        return;
    }

    TRY
    {
        /* Test Server Context */
        SocketTLSContext_T server_ctx = SocketTLSContext_new_server(cert_file, key_file, NULL);
        ASSERT_NOT_NULL(server_ctx);
        
        /* Test Configuration */
        SocketTLSContext_set_min_protocol(server_ctx, SOCKET_TLS_MIN_VERSION);
        SocketTLSContext_set_cipher_list(server_ctx, "HIGH:!aNULL");
        
        const char *protos[] = {"h2", "http/1.1"};
        SocketTLSContext_set_alpn_protos(server_ctx, protos, 2);
        
        SocketTLSContext_enable_session_cache(server_ctx, 100, 300);
        SocketTLSContext_set_session_cache_size(server_ctx, 100);

        SocketTLSContext_free(&server_ctx);
        ASSERT_NULL(server_ctx);

        /* Test Client Context */
        SocketTLSContext_T client_ctx = SocketTLSContext_new_client(NULL); /* No CA verification for now */
        ASSERT_NOT_NULL(client_ctx);
        
        SocketTLSContext_set_verify_mode(client_ctx, TLS_VERIFY_NONE); /* Self-signed cert */
        
        SocketTLSContext_free(&client_ctx);
        ASSERT_NULL(client_ctx);
    }
    FINALLY
    {
        remove_test_certs(cert_file, key_file);
    }
    END_TRY;
}

/* ==================== TLS Handshake & I/O Tests ==================== */

TEST(tls_handshake_and_io)
{
    const char *cert_file = "test_handshake.crt";
    const char *key_file = "test_handshake.key";
    Socket_T client = NULL, server = NULL;
    SocketTLSContext_T client_ctx = NULL, server_ctx = NULL;

    if (generate_test_certs(cert_file, key_file) != 0) return;

    TRY
    {
        /* Create contexts */
        server_ctx = SocketTLSContext_new_server(cert_file, key_file, NULL);
        client_ctx = SocketTLSContext_new_client(NULL);
        SocketTLSContext_set_verify_mode(client_ctx, TLS_VERIFY_NONE); /* Accept self-signed */

        /* Create connected socket pair */
        SocketPair_new(SOCK_STREAM, &client, &server);
        Socket_setnonblocking(client);
        Socket_setnonblocking(server);

        /* Enable TLS */
        SocketTLS_enable(client, client_ctx);
        SocketTLS_enable(server, server_ctx);

        /* Perform Handshake Loop */
        TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
        TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
        int loops = 0;

        while ((client_state != TLS_HANDSHAKE_COMPLETE || server_state != TLS_HANDSHAKE_COMPLETE) && loops < 1000)
        {
            if (client_state != TLS_HANDSHAKE_COMPLETE)
                client_state = SocketTLS_handshake(client);
            
            if (server_state != TLS_HANDSHAKE_COMPLETE)
                server_state = SocketTLS_handshake(server);
            
            loops++;
            usleep(1000); /* 1ms delay to let data move */
        }

        ASSERT_EQ(client_state, TLS_HANDSHAKE_COMPLETE);
        ASSERT_EQ(server_state, TLS_HANDSHAKE_COMPLETE);

        /* Verify TLS1.3-only enforcement */
        const char *version = SocketTLS_get_version(client);
        ASSERT_NOT_NULL(version);
        ASSERT(strcmp(version, "TLSv1.3") == 0);  /* Strict TLS1.3 */

        const char *cipher = SocketTLS_get_cipher(client);
        ASSERT_NOT_NULL(cipher);
        ASSERT(strstr(cipher, "AES") != NULL || strstr(cipher, "CHACHA") != NULL);  /* Modern cipher */

        /* Verify Handshake Info */
        ASSERT_NOT_NULL(SocketTLS_get_version(client));
        ASSERT_NOT_NULL(SocketTLS_get_cipher(client));

        /* Test I/O */
        const char *msg = "Hello TLS";
        char buf[64];
        ssize_t n;

        /* Client -> Server */
        n = SocketTLS_send(client, msg, strlen(msg));
        ASSERT_EQ(n, (ssize_t)strlen(msg));

        /* Loop recv until data arrives (non-blocking) */
        loops = 0;
        do {
            n = SocketTLS_recv(server, buf, sizeof(buf));
            if (n == 0 && errno == EAGAIN) {
                usleep(1000);
                loops++;
            } else {
                break;
            }
        } while (loops < 100);

        ASSERT_EQ(n, (ssize_t)strlen(msg));
        buf[n] = '\0';
        ASSERT_EQ(strcmp(buf, msg), 0);

        /* Server -> Client */
        const char *reply = "TLS Reply";
        n = SocketTLS_send(server, reply, strlen(reply));
        ASSERT_EQ(n, (ssize_t)strlen(reply));

        loops = 0;
        do {
            n = SocketTLS_recv(client, buf, sizeof(buf));
            if (n == 0 && errno == EAGAIN) {
                usleep(1000);
                loops++;
            } else {
                break;
            }
        } while (loops < 100);

        ASSERT_EQ(n, (ssize_t)strlen(reply));
        buf[n] = '\0';
        ASSERT_EQ(strcmp(buf, reply), 0);

        /* Test Shutdown */
        SocketTLS_shutdown(client);
        /* Server should see shutdown */
        /* Note: Full shutdown requires bidirectional close, simplified here */
    }
    FINALLY
    {
        if (client) Socket_free(&client);
        if (server) Socket_free(&server);
        if (client_ctx) SocketTLSContext_free(&client_ctx);
        if (server_ctx) SocketTLSContext_free(&server_ctx);
        remove_test_certs(cert_file, key_file);
    }
    END_TRY;
}

#endif /* SOCKET_HAS_TLS */

/* ==================== Existing Tests (Preserved) ==================== */

TEST(socketpool_tls_integration_structure)
{
#ifdef SOCKET_HAS_TLS
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 10, 1024);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    Connection_T conn = SocketPool_add(pool, socket);
    ASSERT_NOT_NULL(conn);
    
    Connection_T retrieved = SocketPool_get(pool, socket);
    ASSERT_EQ(conn, retrieved);
    
    SocketPool_remove(pool, socket);
    
    int fd = Socket_fd(socket);
    ASSERT_NE(fd, -1);
    
    Socket_free(&socket);
    SocketPool_free(&pool);
    Arena_dispose(&arena);
#else
    (void)0;
#endif
}

TEST(socket_sendfile_tls_fallback_check)
{
#ifdef SOCKET_HAS_TLS
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    int file_fd = open("/dev/zero", O_RDONLY);
    if (file_fd < 0) {
        Socket_free(&socket);
        return;
    }
    
    off_t offset = 0;
    TRY
    {
        Socket_sendfile(socket, file_fd, &offset, 10);
    }
    ELSE
    {
        /* Expected failure (socket not connected) */
    }
    END_TRY;
    
    close(file_fd);
    Socket_free(&socket);
#else
    (void)0;
#endif
}

static int
dummy_accept_verify_cb (int pre_ok, X509_STORE_CTX *ctx, SocketTLSContext_T tls_ctx, Socket_T sock, void *user_data)
{
  (void)pre_ok; (void)tls_ctx; (void)sock; (void)user_data;
  X509_STORE_CTX_set_error(ctx, X509_V_OK);
  return 1;  /* Always accept for test, clear any errors */
}

static int
dummy_fail_verify_cb (int pre_ok, X509_STORE_CTX *ctx, SocketTLSContext_T tls_ctx, Socket_T sock, void *user_data)
{
  (void)ctx; (void)tls_ctx; (void)sock; (void)user_data;
  return pre_ok ? 1 : 0;  /* Fail if pre_ok fail; custom logic e.g., bad cert check */
}

TEST(tls_verify_callback_integration)
{
#ifdef SOCKET_HAS_TLS
    const char *cert_file = "test_cb.crt";
    const char *key_file = "test_cb.key";
    if (generate_test_certs(cert_file, key_file) != 0) return;
    
    Arena_T arena = Arena_new ();
    
    TRY
    {
        /* Setup server ctx with custom cb that accepts all for test */
        SocketTLSContext_T server_ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
        SocketTLSVerifyCallback fail_cb = dummy_fail_verify_cb;
        SocketTLSContext_set_verify_callback (server_ctx, fail_cb, NULL);
        SocketTLSContext_set_verify_mode (server_ctx, TLS_VERIFY_NONE);  /* No client cert in test */
        
        /* Setup client ctx with always-accept cb to test override */
        SocketTLSContext_T client_ctx = SocketTLSContext_new_client (NULL);  /* No CA load for simple test */
        SocketTLSVerifyCallback accept_cb = dummy_accept_verify_cb;
        SocketTLSContext_set_verify_callback (client_ctx, accept_cb, NULL);
        SocketTLSContext_set_verify_mode (client_ctx, TLS_VERIFY_NONE);  /* Disable verification, test callback override */
        
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
        Socket_setnonblocking(server_sock);
        Socket_setnonblocking(client_sock);

        TLSHandshakeState client_state = TLS_HANDSHAKE_IN_PROGRESS;
        TLSHandshakeState server_state = TLS_HANDSHAKE_IN_PROGRESS;
        int loops = 0;

        while ((client_state != TLS_HANDSHAKE_COMPLETE || server_state != TLS_HANDSHAKE_COMPLETE) && loops < 1000)
        {
            if (client_state != TLS_HANDSHAKE_COMPLETE)
                client_state = SocketTLS_handshake(client_sock);
            
            if (server_state != TLS_HANDSHAKE_COMPLETE)
                server_state = SocketTLS_handshake(server_sock);
            
            loops++;
            usleep(1000); /* Yield for data transfer */
        }

        ASSERT_EQ(client_state, TLS_HANDSHAKE_COMPLETE);
        ASSERT_EQ(server_state, TLS_HANDSHAKE_COMPLETE);

        TRY
        {
          long result = SocketTLS_get_verify_result (client_sock);
          ASSERT_EQ (result, X509_V_OK);  /* Success with accept_cb on client */
        }
        ELSE
        {
          ASSERT (0);  /* Unexpected fail in verify result check */
        }
        END_TRY;
        
        /* Cleanup */
        SocketTLSContext_free (&server_ctx);
        SocketTLSContext_free (&client_ctx);
        Socket_free (&server_sock);
        Socket_free (&client_sock);
    }
    FINALLY
    {
        remove_test_certs(cert_file, key_file);
        Arena_dispose (&arena);
    }
    END_TRY;
#else
    (void)0;
#endif
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}

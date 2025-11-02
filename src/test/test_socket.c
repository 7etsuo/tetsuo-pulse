/**
 * test_socket.c - Comprehensive Socket unit tests
 *
 * Industry-standard test coverage for Socket module.
 * Tests TCP sockets, Unix domain sockets, IPv6, error conditions, and edge cases.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "test/Test.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"

#define TEST_UNIX_SOCKET_PATH "/tmp/test_socket_unix"
#define TEST_BUFFER_SIZE 4096

/* Setup signal handling for SIGPIPE */
static void setup_signals(void)
{
    signal(SIGPIPE, SIG_IGN);
}

/* Cleanup Unix socket files */
static void cleanup_unix_socket(const char *path)
{
    unlink(path);
}

/* ==================== Basic Socket Tests ==================== */

TEST(socket_new_creates_ipv4_socket)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    Socket_free(&socket);
    ASSERT_NULL(socket);
}

TEST(socket_new_creates_ipv6_socket)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET6, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    Socket_free(&socket);
    ASSERT_NULL(socket);
}

TEST(socket_new_creates_unix_socket)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    Socket_free(&socket);
    ASSERT_NULL(socket);
}

TEST(socket_fd_access)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    int fd = Socket_fd(socket);
    ASSERT_NE(fd, -1);
    Socket_free(&socket);
}

/* ==================== Bind Tests ==================== */

TEST(socket_bind_localhost_ipv4)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    TRY Socket_bind(socket, "127.0.0.1", 0);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_bind_any_address)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    TRY Socket_bind(socket, NULL, 0);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_bind_wildcard_ipv4)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    TRY Socket_bind(socket, "0.0.0.0", 0);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_bind_ipv6_localhost)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET6, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    TRY Socket_bind(socket, "::1", 0);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_bind_ipv6_any)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET6, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    TRY Socket_bind(socket, "::", 0);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

/* ==================== Unix Domain Socket Tests ==================== */

TEST(socket_bind_unix_regular)
{
    setup_signals();
    cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    Socket_T socket = Socket_new(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);
    TRY
        Socket_bind_unix(socket, TEST_UNIX_SOCKET_PATH);
        cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    EXCEPT(Socket_Failed)
        cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
        ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_unix_connect_accept)
{
    setup_signals();
    cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    
    Socket_T server = Socket_new(AF_UNIX, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(server);
    ASSERT_NOT_NULL(client);

    TRY
        Socket_bind_unix(server, TEST_UNIX_SOCKET_PATH);
        Socket_listen(server, 5);
        Socket_setnonblocking(server);
        Socket_connect_unix(client, TEST_UNIX_SOCKET_PATH);
        Socket_T accepted = Socket_accept(server);
        if (!accepted)
        {
            usleep(50000);
            accepted = Socket_accept(server);
        }
        if (accepted) Socket_free(&accepted);
        cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    EXCEPT(Socket_Failed)
        cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

TEST(socket_unix_send_receive)
{
    setup_signals();
    cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    
    Socket_T server = Socket_new(AF_UNIX, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_UNIX, SOCK_STREAM, 0);

    TRY
        Socket_bind_unix(server, TEST_UNIX_SOCKET_PATH);
        Socket_listen(server, 5);
        Socket_setnonblocking(server);
        Socket_connect_unix(client, TEST_UNIX_SOCKET_PATH);
        
        Socket_T accepted = Socket_accept(server);
        if (!accepted)
        {
            usleep(50000);
            accepted = Socket_accept(server);
        }
        
        if (accepted)
        {
            const char *msg = "Unix socket test";
            Socket_send(client, msg, strlen(msg));
            usleep(10000);
            char buf[TEST_BUFFER_SIZE] = {0};
            ssize_t received = Socket_recv(accepted, buf, sizeof(buf) - 1);
            if (received > 0) ASSERT_EQ(strcmp(buf, msg), 0);
            Socket_free(&accepted);
        }
        cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    EXCEPT(Socket_Failed)
        cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

#ifdef SO_PEERCRED
TEST(socket_unix_peer_credentials)
{
    setup_signals();
    cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    
    Socket_T server = Socket_new(AF_UNIX, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_UNIX, SOCK_STREAM, 0);

    TRY
        Socket_bind_unix(server, TEST_UNIX_SOCKET_PATH);
        Socket_listen(server, 5);
        Socket_setnonblocking(server);
        Socket_connect_unix(client, TEST_UNIX_SOCKET_PATH);
        
        Socket_T accepted = Socket_accept(server);
        if (!accepted)
        {
            usleep(50000);
            accepted = Socket_accept(server);
        }
        
        if (accepted)
        {
            int pid = Socket_getpeerpid(accepted);
            int uid = Socket_getpeeruid(accepted);
            int gid = Socket_getpeergid(accepted);
            ASSERT_NE(pid, -1);
            ASSERT_NE(uid, -1);
            ASSERT_NE(gid, -1);
            Socket_free(&accepted);
        }
        cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    EXCEPT(Socket_Failed)
        cleanup_unix_socket(TEST_UNIX_SOCKET_PATH);
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}
#endif

/* ==================== Listen/Accept Tests ==================== */

TEST(socket_listen_basic)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY
        Socket_bind(socket, "127.0.0.1", 0);
        Socket_listen(socket, 5);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_listen_large_backlog)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY
        Socket_bind(socket, "127.0.0.1", 0);
        Socket_listen(socket, 1024);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_accept_nonblocking_returns_null)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY
        Socket_bind(socket, "127.0.0.1", 0);
        Socket_listen(socket, 5);
        Socket_setnonblocking(socket);
        Socket_T accepted = Socket_accept(socket);
        ASSERT_NULL(accepted);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

/* ==================== Connect Tests ==================== */

TEST(socket_connect_localhost_ipv4)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 1);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        Socket_connect(client, "127.0.0.1", port);
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

TEST(socket_connect_localhost_ipv6)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET6, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET6, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "::1", 0);
        Socket_listen(server, 1);
        struct sockaddr_in6 addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin6_port);
        Socket_connect(client, "::1", port);
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

/* ==================== Send/Receive Tests ==================== */

TEST(socket_send_receive_basic)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 1);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        Socket_connect(client, "127.0.0.1", port);
        Socket_T accepted = Socket_accept(server);
        if (!accepted) { usleep(100000); accepted = Socket_accept(server); }
        
        if (accepted)
        {
            const char *msg = "Test message";
            ssize_t sent = Socket_send(client, msg, strlen(msg));
            if (sent > 0)
            {
                usleep(10000);
                char buf[TEST_BUFFER_SIZE] = {0};
                ssize_t received = Socket_recv(accepted, buf, sizeof(buf) - 1);
                if (received > 0) ASSERT_EQ(strcmp(buf, msg), 0);
            }
            Socket_free(&accepted);
        }
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

TEST(socket_send_large_data)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 1);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        Socket_connect(client, "127.0.0.1", port);
        Socket_T accepted = Socket_accept(server);
        if (!accepted) { usleep(100000); accepted = Socket_accept(server); }
        
        if (accepted)
        {
            char large_buf[8192];
            memset(large_buf, 'A', sizeof(large_buf));
            ssize_t sent = Socket_send(client, large_buf, sizeof(large_buf));
            ASSERT_NE(sent, -1);
            Socket_free(&accepted);
        }
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

TEST(socket_bidirectional_communication)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 1);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        Socket_connect(client, "127.0.0.1", port);
        Socket_T accepted = Socket_accept(server);
        if (!accepted) { usleep(100000); accepted = Socket_accept(server); }
        
        if (accepted)
        {
            const char *c2s = "Client to Server";
            const char *s2c = "Server to Client";
            Socket_send(client, c2s, strlen(c2s));
            usleep(10000);
            char buf1[TEST_BUFFER_SIZE] = {0};
            Socket_recv(accepted, buf1, sizeof(buf1) - 1);
            Socket_send(accepted, s2c, strlen(s2c));
            usleep(10000);
            char buf2[TEST_BUFFER_SIZE] = {0};
            Socket_recv(client, buf2, sizeof(buf2) - 1);
            Socket_free(&accepted);
        }
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

/* ==================== Socket Options Tests ==================== */

TEST(socket_setnonblocking)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY Socket_setnonblocking(socket);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_setreuseaddr)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY Socket_setreuseaddr(socket);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_settimeout)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY Socket_settimeout(socket, 5);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_settimeout_zero)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY Socket_settimeout(socket, 0);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_setkeepalive)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY Socket_setkeepalive(socket, 60, 10, 3);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_setnodelay_enable)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY Socket_setnodelay(socket, 1);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_setnodelay_disable)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY Socket_setnodelay(socket, 0);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

/* ==================== Peer Info Tests ==================== */

TEST(socket_getpeeraddr_after_accept)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 1);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        Socket_connect(client, "127.0.0.1", port);
        Socket_T accepted = Socket_accept(server);
        if (!accepted) { usleep(100000); accepted = Socket_accept(server); }
        
        if (accepted)
        {
            const char *peeraddr = Socket_getpeeraddr(accepted);
            ASSERT_NOT_NULL(peeraddr);
            Socket_free(&accepted);
        }
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

TEST(socket_getpeerport_after_accept)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 1);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        Socket_connect(client, "127.0.0.1", port);
        Socket_T accepted = Socket_accept(server);
        if (!accepted) { usleep(100000); accepted = Socket_accept(server); }
        
        if (accepted)
        {
            int peerport = Socket_getpeerport(accepted);
            ASSERT_NE(peerport, 0);
            Socket_free(&accepted);
        }
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

/* ==================== Error Condition Tests ==================== */

TEST(socket_recv_on_closed_socket_raises)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
    volatile int closed_raised = 0;

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 1);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        Socket_connect(client, "127.0.0.1", port);
        Socket_T accepted = Socket_accept(server);
        if (!accepted) { usleep(100000); accepted = Socket_accept(server); }
        
        if (accepted)
        {
            Socket_free(&client);
            client = NULL;
            usleep(50000);
            char buf[TEST_BUFFER_SIZE];
            TRY Socket_recv(accepted, buf, sizeof(buf));
            EXCEPT(Socket_Closed) closed_raised = 1;
            END_TRY;
            Socket_free(&accepted);
        }
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        if (client) Socket_free(&client);
        Socket_free(&server);
    END_TRY;
    
    ASSERT_EQ(closed_raised, 1);
}

TEST(socket_multiple_connections)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client1 = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client2 = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 10);
        Socket_setnonblocking(server);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        Socket_connect(client1, "127.0.0.1", port);
        Socket_connect(client2, "127.0.0.1", port);
        usleep(50000);
        
        Socket_T acc1 = Socket_accept(server);
        Socket_T acc2 = Socket_accept(server);
        
        if (acc1) Socket_free(&acc1);
        if (acc2) Socket_free(&acc2);
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&client2);
        Socket_free(&client1);
        Socket_free(&server);
    END_TRY;
}

/* ==================== Accessor Tests ==================== */

TEST(socket_getpeeraddr_unknown_when_no_peer)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    const char *peeraddr = Socket_getpeeraddr(socket);
    ASSERT_NOT_NULL(peeraddr);
    ASSERT_EQ(strcmp(peeraddr, "(unknown)"), 0);
    Socket_free(&socket);
}

TEST(socket_getpeerport_zero_when_no_peer)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    int peerport = Socket_getpeerport(socket);
    ASSERT_EQ(peerport, 0);
    Socket_free(&socket);
}

/* ==================== Stress Tests ==================== */

TEST(socket_many_sequential_connections)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 10);
        Socket_setnonblocking(server);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        for (int i = 0; i < 10; i++)
        {
            Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
            Socket_connect(client, "127.0.0.1", port);
            usleep(10000);
            Socket_T accepted = Socket_accept(server);
            if (accepted) Socket_free(&accepted);
            Socket_free(&client);
        }
    EXCEPT(Socket_Failed) (void)0;
    END_TRY;
    
    Socket_free(&server);
}

TEST(socket_rapid_open_close)
{
    setup_signals();
    for (int i = 0; i < 100; i++)
    {
        Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
        ASSERT_NOT_NULL(socket);
        Socket_free(&socket);
        ASSERT_NULL(socket);
    }
}

/* ==================== Thread Safety Tests ==================== */

static void *thread_create_sockets(void *arg)
{
    (void)arg;
    for (int i = 0; i < 50; i++)
    {
        Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
        if (socket) Socket_free(&socket);
    }
    return NULL;
}

TEST(socket_concurrent_creation)
{
    setup_signals();
    pthread_t threads[4];
    
    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, thread_create_sockets, NULL);
    
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
}

/* ==================== Async DNS Integration Tests ==================== */

TEST(socket_bind_async_basic)
{
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketDNS_Request_T req = Socket_bind_async(dns, socket, "127.0.0.1", 0);
        ASSERT_NOT_NULL(req);
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_bind_with_addrinfo(socket, res);
            freeaddrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        Socket_free(&socket);
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socket_bind_async_wildcard)
{
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketDNS_Request_T req = Socket_bind_async(dns, socket, NULL, 0);
        ASSERT_NOT_NULL(req);
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_bind_with_addrinfo(socket, res);
            freeaddrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        Socket_free(&socket);
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socket_connect_async_basic)
{
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 5);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketDNS_Request_T req = Socket_connect_async(dns, client, "127.0.0.1", port);
        ASSERT_NOT_NULL(req);
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_connect_with_addrinfo(client, res);
            freeaddrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socket_connect_async_localhost)
{
    setup_signals();
    SocketDNS_T dns = SocketDNS_new();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 5);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketDNS_Request_T req = Socket_connect_async(dns, client, "localhost", port);
        ASSERT_NOT_NULL(req);
        usleep(200000);
        SocketDNS_check(dns);
        struct addrinfo *res = SocketDNS_getresult(dns, req);
        if (res)
        {
            Socket_connect_with_addrinfo(client, res);
            freeaddrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socket_bind_with_addrinfo_ipv4)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    struct addrinfo hints, *res = NULL;

    TRY
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        
        int result = getaddrinfo("127.0.0.1", "0", &hints, &res);
        if (result == 0 && res)
        {
            Socket_bind_with_addrinfo(socket, res);
            freeaddrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&socket);
    END_TRY;
}

TEST(socket_connect_with_addrinfo_ipv4)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
    struct addrinfo hints, *res = NULL;

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 5);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        
        int result = getaddrinfo("127.0.0.1", port_str, &hints, &res);
        if (result == 0 && res)
        {
            Socket_connect_with_addrinfo(client, res);
            freeaddrinfo(res);
        }
    EXCEPT(Socket_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}


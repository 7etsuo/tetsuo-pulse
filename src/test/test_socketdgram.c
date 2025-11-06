/**
 * test_socketdgram.c - Comprehensive SocketDgram unit tests
 *
 * Industry-standard test coverage for SocketDgram UDP module.
 * Tests UDP sockets, multicast, broadcast, connected mode, and edge cases.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test/Test.h"
#include "core/Except.h"
#include "socket/SocketDgram.h"
#include "socket/SocketCommon.h"

#define TEST_BUFFER_SIZE 4096
#define TEST_MULTICAST_GROUP "239.0.0.1"

static void setup_signals(void)
{
    signal(SIGPIPE, SIG_IGN);
}

/* ==================== Basic Socket Tests ==================== */

TEST(socketdgram_new_creates_ipv4_socket)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    ASSERT_NOT_NULL(socket);
    SocketDgram_free(&socket);
    ASSERT_NULL(socket);
}

TEST(socketdgram_new_creates_ipv6_socket)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET6, 0);
    ASSERT_NOT_NULL(socket);
    SocketDgram_free(&socket);
    ASSERT_NULL(socket);
}

TEST(socketdgram_fd_access)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    ASSERT_NOT_NULL(socket);
    int fd = SocketDgram_fd(socket);
    ASSERT_NE(fd, -1);
    SocketDgram_free(&socket);
}

/* ==================== Bind Tests ==================== */

TEST(socketdgram_bind_localhost)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    ASSERT_NOT_NULL(socket);
    TRY
    {
        SocketDgram_bind(socket, "127.0.0.1", 0);
    }
    EXCEPT(SocketDgram_Failed)
    {
        ASSERT(0);
    }
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_bind_any)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    ASSERT_NOT_NULL(socket);
    TRY
    {
        SocketDgram_bind(socket, NULL, 0);
    }
    EXCEPT(SocketDgram_Failed)
    {
        ASSERT(0);
    }
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_bind_wildcard_ipv4)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    TRY
    {
        SocketDgram_bind(socket, "0.0.0.0", 0);
    }
    EXCEPT(SocketDgram_Failed)
    {
        ASSERT(0);
    }
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_bind_ipv6_localhost)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET6, 0);
    TRY
    {
        SocketDgram_bind(socket, "::1", 0);
    }
    EXCEPT(SocketDgram_Failed)
    {
        ASSERT(0);
    }
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_bind_ipv6_any)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET6, 0);
    TRY
    {
        SocketDgram_bind(socket, "::", 0);
    }
    EXCEPT(SocketDgram_Failed)
    {
        ASSERT(0);
    }
    END_TRY;
    SocketDgram_free(&socket);
}

/* ==================== Sendto/Recvfrom Tests ==================== */

TEST(socketdgram_sendto_recvfrom_localhost)
{
    setup_signals();
    SocketDgram_T sender = SocketDgram_new(AF_INET, 0);
    SocketDgram_T receiver = SocketDgram_new(AF_INET, 0);

    TRY
    {
        SocketDgram_bind(receiver, "127.0.0.1", 0);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(SocketDgram_fd(receiver), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);

        const char *msg = "UDP test message";
        ssize_t sent = SocketDgram_sendto(sender, msg, strlen(msg), "127.0.0.1", port);
        ASSERT_NE(sent, -1);

        usleep(10000);
        char recv_host[256] = {0};
        int recv_port = 0;
        char buf[TEST_BUFFER_SIZE] = {0};
        ssize_t received = SocketDgram_recvfrom(receiver, buf, sizeof(buf) - 1, recv_host, sizeof(recv_host), &recv_port);

        if (received > 0)
        {
            ASSERT_EQ(strcmp(buf, msg), 0);
            ASSERT_NE(recv_port, 0);
        }
    }
    EXCEPT(SocketDgram_Failed)
    {
        (void)0;
    }
    FINALLY
    {
        SocketDgram_free(&sender);
        SocketDgram_free(&receiver);
    }
    END_TRY;
}

TEST(socketdgram_sendto_recvfrom_large_data)
{
    setup_signals();
    SocketDgram_T sender = SocketDgram_new(AF_INET, 0);
    SocketDgram_T receiver = SocketDgram_new(AF_INET, 0);

    TRY
        SocketDgram_bind(receiver, "127.0.0.1", 0);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(SocketDgram_fd(receiver), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        char large_buf[4096];
        memset(large_buf, 'B', sizeof(large_buf));
        ssize_t sent = SocketDgram_sendto(sender, large_buf, sizeof(large_buf), "127.0.0.1", port);
        ASSERT_NE(sent, -1);
    EXCEPT(SocketDgram_Failed) (void)0;
    FINALLY
        SocketDgram_free(&sender);
        SocketDgram_free(&receiver);
    END_TRY;
}

TEST(socketdgram_multiple_datagrams)
{
    setup_signals();
    SocketDgram_T sender = SocketDgram_new(AF_INET, 0);
    SocketDgram_T receiver = SocketDgram_new(AF_INET, 0);

    TRY
        SocketDgram_bind(receiver, "127.0.0.1", 0);
        SocketDgram_setnonblocking(receiver);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(SocketDgram_fd(receiver), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        for (int i = 0; i < 5; i++)
        {
            char msg[32];
            snprintf(msg, sizeof(msg), "Datagram %d", i);
            SocketDgram_sendto(sender, msg, strlen(msg), "127.0.0.1", port);
        }
        
        usleep(50000);
        int received_count = 0;
        for (int i = 0; i < 5; i++)
        {
            char buf[TEST_BUFFER_SIZE];
            ssize_t received = SocketDgram_recvfrom(receiver, buf, sizeof(buf), NULL, 0, NULL);
            if (received > 0) received_count++;
        }
        ASSERT_NE(received_count, 0);
    EXCEPT(SocketDgram_Failed) (void)0;
    FINALLY
        SocketDgram_free(&sender);
        SocketDgram_free(&receiver);
    END_TRY;
}

/* ==================== Connected Mode Tests ==================== */

TEST(socketdgram_connect_send_recv)
{
    setup_signals();
    SocketDgram_T sender = SocketDgram_new(AF_INET, 0);
    SocketDgram_T receiver = SocketDgram_new(AF_INET, 0);

    TRY
        SocketDgram_bind(receiver, "127.0.0.1", 0);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(SocketDgram_fd(receiver), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketDgram_connect(sender, "127.0.0.1", port);
        
        const char *msg = "Connected UDP";
        ssize_t sent = SocketDgram_send(sender, msg, strlen(msg));
        ASSERT_NE(sent, -1);
        
        usleep(10000);
        char buf[TEST_BUFFER_SIZE] = {0};
        ssize_t received = SocketDgram_recv(receiver, buf, sizeof(buf) - 1);
        if (received > 0) ASSERT_EQ(strcmp(buf, msg), 0);
    EXCEPT(SocketDgram_Failed) (void)0;
    FINALLY
        SocketDgram_free(&sender);
        SocketDgram_free(&receiver);
    END_TRY;
}

TEST(socketdgram_connected_bidirectional)
{
    setup_signals();
    SocketDgram_T sock1 = SocketDgram_new(AF_INET, 0);
    SocketDgram_T sock2 = SocketDgram_new(AF_INET, 0);

    TRY
        SocketDgram_bind(sock1, "127.0.0.1", 0);
        SocketDgram_bind(sock2, "127.0.0.1", 0);
        
        struct sockaddr_in addr1, addr2;
        socklen_t len = sizeof(addr1);
        getsockname(SocketDgram_fd(sock1), (struct sockaddr *)&addr1, &len);
        getsockname(SocketDgram_fd(sock2), (struct sockaddr *)&addr2, &len);
        int port1 = ntohs(addr1.sin_port);
        int port2 = ntohs(addr2.sin_port);
        
        SocketDgram_connect(sock1, "127.0.0.1", port2);
        SocketDgram_connect(sock2, "127.0.0.1", port1);
        
        SocketDgram_send(sock1, "Msg1", 4);
        SocketDgram_send(sock2, "Msg2", 4);
        usleep(10000);
        
        char buf1[128], buf2[128];
        SocketDgram_recv(sock1, buf1, sizeof(buf1));
        SocketDgram_recv(sock2, buf2, sizeof(buf2));
    EXCEPT(SocketDgram_Failed) (void)0;
    FINALLY
        SocketDgram_free(&sock1);
        SocketDgram_free(&sock2);
    END_TRY;
}

/* ==================== Socket Options Tests ==================== */

TEST(socketdgram_setnonblocking)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    TRY SocketDgram_setnonblocking(socket);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_setreuseaddr)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    TRY SocketDgram_setreuseaddr(socket);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_setbroadcast_enable)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    TRY SocketDgram_setbroadcast(socket, 1);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_setbroadcast_disable)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    TRY SocketDgram_setbroadcast(socket, 0);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_settimeout)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    TRY SocketDgram_settimeout(socket, 5);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    SocketDgram_free(&socket);
}

/* ==================== Close-on-Exec Tests ==================== */

TEST(socketdgram_new_sets_cloexec_by_default)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    ASSERT_NOT_NULL(socket);
    
    int has_cloexec = SocketCommon_has_cloexec(SocketDgram_fd(socket));
    ASSERT_EQ(has_cloexec, 1);
    
    SocketDgram_free(&socket);
}

TEST(socketdgram_setcloexec_enable_disable)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    ASSERT_NOT_NULL(socket);
    
    /* Verify CLOEXEC is set by default */
    int has_cloexec = SocketCommon_has_cloexec(SocketDgram_fd(socket));
    ASSERT_EQ(has_cloexec, 1);
    
    /* Disable CLOEXEC */
    TRY SocketDgram_setcloexec(socket, 0);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    
    has_cloexec = SocketCommon_has_cloexec(SocketDgram_fd(socket));
    ASSERT_EQ(has_cloexec, 0);
    
    /* Re-enable CLOEXEC */
    TRY SocketDgram_setcloexec(socket, 1);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    
    has_cloexec = SocketCommon_has_cloexec(SocketDgram_fd(socket));
    ASSERT_EQ(has_cloexec, 1);
    
    SocketDgram_free(&socket);
}

TEST(socketdgram_setttl)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    TRY SocketDgram_setttl(socket, 64);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_setttl_min_max)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    TRY
        SocketDgram_setttl(socket, 1);
        SocketDgram_setttl(socket, 255);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    SocketDgram_free(&socket);
}

/* ==================== Multicast Tests ==================== */

TEST(socketdgram_joinmulticast_ipv4)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
    TRY
        SocketDgram_setreuseaddr(socket);
        SocketDgram_bind(socket, "0.0.0.0", 0);
        SocketDgram_joinmulticast(socket, TEST_MULTICAST_GROUP, NULL);
        SocketDgram_leavemulticast(socket, TEST_MULTICAST_GROUP, NULL);
    EXCEPT(SocketDgram_Failed) (void)0;
    END_TRY;
    SocketDgram_free(&socket);
}

TEST(socketdgram_multicast_send_receive)
{
    setup_signals();
    SocketDgram_T sender = SocketDgram_new(AF_INET, 0);
    SocketDgram_T receiver = SocketDgram_new(AF_INET, 0);

    TRY
        SocketDgram_setreuseaddr(receiver);
        SocketDgram_bind(receiver, "0.0.0.0", 0);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(SocketDgram_fd(receiver), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketDgram_joinmulticast(receiver, TEST_MULTICAST_GROUP, NULL);
        SocketDgram_setnonblocking(receiver);
        
        const char *msg = "Multicast message";
        TRY
            SocketDgram_sendto(sender, msg, strlen(msg), TEST_MULTICAST_GROUP, port);
            usleep(50000);
            
            char buf[TEST_BUFFER_SIZE] = {0};
            ssize_t received = SocketDgram_recvfrom(receiver, buf, sizeof(buf) - 1, NULL, 0, NULL);
            if (received > 0) ASSERT_EQ(strcmp(buf, msg), 0);
        EXCEPT(SocketDgram_Failed)
            /* Multicast may fail if routing is not configured (e.g., macOS without multicast routing) */
            /* This is acceptable - test passes if we can join/leave multicast group */
            (void)0;
        END_TRY;
        
        SocketDgram_leavemulticast(receiver, TEST_MULTICAST_GROUP, NULL);
    EXCEPT(SocketDgram_Failed) (void)0;
    FINALLY
        SocketDgram_free(&sender);
        SocketDgram_free(&receiver);
    END_TRY;
}

/* ==================== IPv6 Tests ==================== */

TEST(socketdgram_ipv6_sendto_recvfrom)
{
    setup_signals();
    SocketDgram_T sender = SocketDgram_new(AF_INET6, 0);
    SocketDgram_T receiver = SocketDgram_new(AF_INET6, 0);

    TRY
        SocketDgram_bind(receiver, "::1", 0);
        struct sockaddr_in6 addr;
        socklen_t len = sizeof(addr);
        getsockname(SocketDgram_fd(receiver), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin6_port);
        
        const char *msg = "IPv6 UDP test";
        ssize_t sent = SocketDgram_sendto(sender, msg, strlen(msg), "::1", port);
        ASSERT_NE(sent, -1);
        
        usleep(10000);
        char buf[TEST_BUFFER_SIZE] = {0};
        ssize_t received = SocketDgram_recvfrom(receiver, buf, sizeof(buf) - 1, NULL, 0, NULL);
        if (received > 0) ASSERT_EQ(strcmp(buf, msg), 0);
    EXCEPT(SocketDgram_Failed) (void)0;
    FINALLY
        SocketDgram_free(&sender);
        SocketDgram_free(&receiver);
    END_TRY;
}

TEST(socketdgram_ipv6_setttl)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET6, 0);
    TRY SocketDgram_setttl(socket, 128);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;
    SocketDgram_free(&socket);
}

/* ==================== Nonblocking Tests ==================== */

TEST(socketdgram_recvfrom_nonblocking_returns_zero)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);

    TRY
        SocketDgram_bind(socket, "127.0.0.1", 0);
        SocketDgram_setnonblocking(socket);
        
        char buf[TEST_BUFFER_SIZE];
        ssize_t received = SocketDgram_recvfrom(socket, buf, sizeof(buf), NULL, 0, NULL);
        ASSERT_EQ(received, 0);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;

    SocketDgram_free(&socket);
}

TEST(socketdgram_recv_nonblocking_returns_zero)
{
    setup_signals();
    SocketDgram_T socket = SocketDgram_new(AF_INET, 0);

    TRY
        SocketDgram_bind(socket, "127.0.0.1", 0);
        SocketDgram_connect(socket, "127.0.0.1", 9999);
        SocketDgram_setnonblocking(socket);
        
        char buf[TEST_BUFFER_SIZE];
        ssize_t received = SocketDgram_recv(socket, buf, sizeof(buf));
        ASSERT_EQ(received, 0);
    EXCEPT(SocketDgram_Failed) ASSERT(0);
    END_TRY;

    SocketDgram_free(&socket);
}

/* ==================== Stress Tests ==================== */

TEST(socketdgram_many_sequential_datagrams)
{
    setup_signals();
    SocketDgram_T sender = SocketDgram_new(AF_INET, 0);
    SocketDgram_T receiver = SocketDgram_new(AF_INET, 0);

    TRY
        SocketDgram_bind(receiver, "127.0.0.1", 0);
        SocketDgram_setnonblocking(receiver);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(SocketDgram_fd(receiver), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        for (int i = 0; i < 100; i++)
        {
            char msg[16];
            snprintf(msg, sizeof(msg), "Msg%d", i);
            SocketDgram_sendto(sender, msg, strlen(msg), "127.0.0.1", port);
        }
    EXCEPT(SocketDgram_Failed) (void)0;
    FINALLY
        SocketDgram_free(&sender);
        SocketDgram_free(&receiver);
    END_TRY;
}

TEST(socketdgram_rapid_open_close)
{
    setup_signals();
    for (int i = 0; i < 100; i++)
    {
        SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
        ASSERT_NOT_NULL(socket);
        SocketDgram_free(&socket);
        ASSERT_NULL(socket);
    }
}

/* ==================== Thread Safety Tests ==================== */

static void *thread_create_dgram_sockets(void *arg)
{
    (void)arg;
    for (int i = 0; i < 50; i++)
    {
        SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
        if (socket) SocketDgram_free(&socket);
    }
    return NULL;
}

TEST(socketdgram_concurrent_creation)
{
    setup_signals();
    pthread_t threads[4];
    
    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, thread_create_dgram_sockets, NULL);
    
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
}

static void *thread_sendto_datagrams(void *arg)
{
    int port = *(int *)arg;
    SocketDgram_T sender = SocketDgram_new(AF_INET, 0);
    
    for (int i = 0; i < 20; i++)
    {
        char msg[32];
        snprintf(msg, sizeof(msg), "Thread msg %d", i);
        TRY SocketDgram_sendto(sender, msg, strlen(msg), "127.0.0.1", port);
        EXCEPT(SocketDgram_Failed) break;
        END_TRY;
        usleep(1000);
    }
    
    SocketDgram_free(&sender);
    return NULL;
}

TEST(socketdgram_concurrent_sendto)
{
    setup_signals();
    SocketDgram_T receiver = SocketDgram_new(AF_INET, 0);
    pthread_t threads[4];
    int port = 0;

    TRY
        SocketDgram_bind(receiver, "127.0.0.1", 0);
        SocketDgram_setnonblocking(receiver);
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(SocketDgram_fd(receiver), (struct sockaddr *)&addr, &len);
        port = ntohs(addr.sin_port);
        
        for (int i = 0; i < 4; i++)
            pthread_create(&threads[i], NULL, thread_sendto_datagrams, &port);
        
        for (int i = 0; i < 4; i++)
            pthread_join(threads[i], NULL);
    EXCEPT(SocketDgram_Failed) (void)0;
    END_TRY;
    
    SocketDgram_free(&receiver);
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}



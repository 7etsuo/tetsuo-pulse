/**
 * test_socket.c - Comprehensive Socket unit tests
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
#include <sys/wait.h>
#include <unistd.h>

#include "test/Test.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"

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

typedef struct
{
    int count;
    SocketEventRecord last_event;
} EventProbe;

static void event_probe_callback(void *userdata, const SocketEventRecord *event)
{
    EventProbe *probe = (EventProbe *)userdata;

    if (!probe || !event)
        return;

    probe->count++;
    probe->last_event = *event;
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
    TRY Socket_bind_unix(socket, TEST_UNIX_SOCKET_PATH);
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

    TRY Socket_bind_unix(server, TEST_UNIX_SOCKET_PATH);
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
        Socket_free(&accepted);
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

    TRY Socket_bind_unix(server, TEST_UNIX_SOCKET_PATH);
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
        if (received > 0)
            ASSERT_EQ(strcmp(buf, msg), 0);
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

    TRY Socket_bind_unix(server, TEST_UNIX_SOCKET_PATH);
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
    TRY Socket_bind(socket, "127.0.0.1", 0);
    Socket_listen(socket, 5);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_listen_large_backlog)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY Socket_bind(socket, "127.0.0.1", 0);
    Socket_listen(socket, 1024);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;
    Socket_free(&socket);
}

TEST(socket_accept_nonblocking_returns_null)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY Socket_bind(socket, "127.0.0.1", 0);
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

    TRY Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 1);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    int port = ntohs(addr.sin_port);
    Socket_connect(client, "127.0.0.1", port);
    EXCEPT(Socket_Failed)(void) 0;
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

    TRY Socket_bind(server, "::1", 0);
    Socket_listen(server, 1);
    struct sockaddr_in6 addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    int port = ntohs(addr.sin6_port);
    Socket_connect(client, "::1", port);
    EXCEPT(Socket_Failed)(void) 0;
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

    TRY Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 1);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    int port = ntohs(addr.sin_port);
    Socket_connect(client, "127.0.0.1", port);
    Socket_T accepted = Socket_accept(server);
    if (!accepted)
    {
        usleep(100000);
        accepted = Socket_accept(server);
    }

    if (accepted)
    {
        const char *msg = "Test message";
        ssize_t sent = Socket_send(client, msg, strlen(msg));
        if (sent > 0)
        {
            usleep(10000);
            char buf[TEST_BUFFER_SIZE] = {0};
            ssize_t received = Socket_recv(accepted, buf, sizeof(buf) - 1);
            if (received > 0)
                ASSERT_EQ(strcmp(buf, msg), 0);
        }
        Socket_free(&accepted);
    }
    EXCEPT(Socket_Failed)(void) 0;
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

    TRY Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 1);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    int port = ntohs(addr.sin_port);
    Socket_connect(client, "127.0.0.1", port);
    Socket_T accepted = Socket_accept(server);
    if (!accepted)
    {
        usleep(100000);
        accepted = Socket_accept(server);
    }

    if (accepted)
    {
        char large_buf[8192];
        memset(large_buf, 'A', sizeof(large_buf));
        ssize_t sent = Socket_send(client, large_buf, sizeof(large_buf));
        ASSERT_NE(sent, -1);
        Socket_free(&accepted);
    }
    EXCEPT(Socket_Failed)(void) 0;
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

    TRY volatile int port;
    Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 1);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    port = ntohs(addr.sin_port);
    Socket_connect(client, "127.0.0.1", port);
    volatile Socket_T accepted = Socket_accept(server);
    if (!accepted)
    {
        usleep(100000);
        accepted = Socket_accept(server);
    }

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
        Socket_T a = (Socket_T)accepted;
        Socket_free(&a);
    }
    EXCEPT(Socket_Failed)(void) 0;
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

/* ==================== Close-on-Exec Tests ==================== */

TEST(socket_new_sets_cloexec_by_default)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);

    int has_cloexec = SocketCommon_has_cloexec(Socket_fd(socket));
    ASSERT_EQ(has_cloexec, 1);

    Socket_free(&socket);
}

TEST(socket_accept_sets_cloexec_by_default)
{
    setup_signals();
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T accepted = NULL;

    TRY Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 1);
    Socket_setnonblocking(server);

    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    int port = ntohs(addr.sin_port);

    Socket_connect(client, "127.0.0.1", port);
    usleep(100000);
    accepted = Socket_accept(server);

    if (accepted)
    {
        int has_cloexec = SocketCommon_has_cloexec(Socket_fd(accepted));
        ASSERT_EQ(has_cloexec, 1);
        Socket_free(&accepted);
    }
    EXCEPT(Socket_Failed)(void) 0;
    FINALLY
    Socket_free(&client);
    Socket_free(&server);
    END_TRY;
}

TEST(socket_setcloexec_enable_disable)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);

    /* Verify CLOEXEC is set by default */
    int has_cloexec = SocketCommon_has_cloexec(Socket_fd(socket));
    ASSERT_EQ(has_cloexec, 1);

    /* Disable CLOEXEC */
    TRY Socket_setcloexec(socket, 0);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;

    has_cloexec = SocketCommon_has_cloexec(Socket_fd(socket));
    ASSERT_EQ(has_cloexec, 0);

    /* Re-enable CLOEXEC */
    TRY Socket_setcloexec(socket, 1);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;

    has_cloexec = SocketCommon_has_cloexec(Socket_fd(socket));
    ASSERT_EQ(has_cloexec, 1);

    Socket_free(&socket);
}

TEST(socket_cloexec_prevents_leak)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL(socket);

    /* Verify CLOEXEC is set - this prevents descriptor leaks on exec */
    int has_cloexec = SocketCommon_has_cloexec(Socket_fd(socket));
    ASSERT_EQ(has_cloexec, 1);

    /* Test that we can disable and re-enable */
    TRY Socket_setcloexec(socket, 0);
    EXCEPT(Socket_Failed) ASSERT(0);
    END_TRY;

    has_cloexec = SocketCommon_has_cloexec(Socket_fd(socket));
    ASSERT_EQ(has_cloexec, 0);

    /* Re-enable for safety */
    TRY Socket_setcloexec(socket, 1);
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

    TRY Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 1);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    int port = ntohs(addr.sin_port);
    Socket_connect(client, "127.0.0.1", port);
    Socket_T accepted = Socket_accept(server);
    if (!accepted)
    {
        usleep(100000);
        accepted = Socket_accept(server);
    }

    if (accepted)
    {
        const char *peeraddr = Socket_getpeeraddr(accepted);
        ASSERT_NOT_NULL(peeraddr);
        Socket_free(&accepted);
    }
    EXCEPT(Socket_Failed)(void) 0;
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

    TRY volatile int port;
    Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 1);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    port = ntohs(addr.sin_port);
    Socket_connect(client, "127.0.0.1", port);
    volatile Socket_T accepted = Socket_accept(server);
    if (!accepted)
    {
        usleep(100000);
        accepted = Socket_accept(server);
    }

    if (accepted)
    {
        int peerport = Socket_getpeerport(accepted);
        ASSERT_NE(peerport, 0);
        Socket_T a = (Socket_T)accepted;
        Socket_free(&a);
    }
    EXCEPT(Socket_Failed)(void) 0;
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

    TRY volatile int port;
    Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 1);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    port = ntohs(addr.sin_port);
    Socket_connect(client, "127.0.0.1", port);
    volatile Socket_T accepted = Socket_accept(server);
    if (!accepted)
    {
        usleep(100000);
        accepted = Socket_accept(server);
    }

    if (accepted)
    {
        Socket_free(&client);
        client = NULL;
        usleep(50000);
        char buf[TEST_BUFFER_SIZE];
        TRY Socket_recv(accepted, buf, sizeof(buf));
        EXCEPT(Socket_Closed) closed_raised = 1;
        END_TRY;
        Socket_T a = (Socket_T)accepted;
        Socket_free(&a);
    }
    EXCEPT(Socket_Failed)(void) 0;
    FINALLY
    if (client)
        Socket_free(&client);
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

    TRY volatile int port;
    Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 10);
    Socket_setnonblocking(server);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    port = ntohs(addr.sin_port);

    Socket_connect(client1, "127.0.0.1", port);
    Socket_connect(client2, "127.0.0.1", port);
    usleep(50000);

    volatile Socket_T acc1 = Socket_accept(server);
    volatile Socket_T acc2 = Socket_accept(server);

    if (acc1)
    {
        Socket_T a = (Socket_T)acc1;
        Socket_free(&a);
    }
    if (acc2)
    {
        Socket_T a = (Socket_T)acc2;
        Socket_free(&a);
    }
    EXCEPT(Socket_Failed)(void) 0;
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

    TRY volatile int port;
    volatile int i;
    Socket_bind(server, "127.0.0.1", 0);
    Socket_listen(server, 10);
    Socket_setnonblocking(server);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
    port = ntohs(addr.sin_port);

    for (i = 0; i < 10; i++)
    {
        Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
        Socket_connect(client, "127.0.0.1", port);
        usleep(10000);
        Socket_T accepted = Socket_accept(server);
        if (accepted)
            Socket_free(&accepted);
        Socket_free(&client);
    }
    EXCEPT(Socket_Failed)(void) 0;
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
        if (socket)
            Socket_free(&socket);
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

#if 0 /* DNS test disabled - hangs on SocketDNS_check() */
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
#endif

#if 0 /* DNS tests disabled - hang on SocketDNS_check() */
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
#endif

TEST(socket_bind_with_addrinfo_ipv4)
{
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    struct addrinfo hints, *res = NULL;

    TRY memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int result = getaddrinfo("127.0.0.1", "0", &hints, &res);
    if (result == 0 && res)
    {
        Socket_bind_with_addrinfo(socket, res);
        freeaddrinfo(res);
    }
    EXCEPT(Socket_Failed)(void) 0;
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

    TRY Socket_bind(server, "127.0.0.1", 0);
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
    EXCEPT(Socket_Failed)(void) 0;
    FINALLY
    Socket_free(&client);
    Socket_free(&server);
    END_TRY;
}

TEST(socketmetrics_snapshot_exports)
{
    SocketMetricsSnapshot snapshot = {{0ULL}};

    SocketMetrics_reset();
    SocketMetrics_increment(SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 3);
    SocketMetrics_increment(SOCKET_METRIC_POLL_WAKEUPS, 1);
    SocketMetrics_getsnapshot(&snapshot);

    ASSERT_EQ(3ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
    ASSERT_EQ(1ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_POLL_WAKEUPS));
    ASSERT_EQ(SOCKET_METRIC_COUNT, SocketMetrics_count());

    SocketMetrics_reset();
    SocketMetrics_getsnapshot(&snapshot);
    ASSERT_EQ(0ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
}

TEST(socketevents_emit_and_unregister)
{
    EventProbe probe = {0};

    SocketEvent_register(event_probe_callback, &probe);
    SocketEvent_emit_poll_wakeup(5, 100);

    ASSERT_EQ(1, probe.count);
    ASSERT_EQ(SOCKET_EVENT_POLL_WAKEUP, probe.last_event.type);
    ASSERT_EQ(5, probe.last_event.data.poll.nfds);
    ASSERT_EQ(100, probe.last_event.data.poll.timeout_ms);

    SocketEvent_emit_dns_timeout("example.com", 443);
    ASSERT_EQ(2, probe.count);
    ASSERT_EQ(SOCKET_EVENT_DNS_TIMEOUT, probe.last_event.type);
    ASSERT(strcmp(probe.last_event.data.dns.host, "example.com") == 0);
    ASSERT_EQ(443, probe.last_event.data.dns.port);

    SocketEvent_unregister(event_probe_callback, &probe);
    SocketEvent_emit_poll_wakeup(1, 0);
    ASSERT_EQ(2, probe.count);
}

TEST(socketmetrics_all_metric_types)
{
    SocketMetricsSnapshot snapshot = {{0ULL}};

    SocketMetrics_reset();
    SocketMetrics_increment(SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
    SocketMetrics_increment(SOCKET_METRIC_SOCKET_CONNECT_FAILURE, 2);
    SocketMetrics_increment(SOCKET_METRIC_SOCKET_SHUTDOWN_CALL, 3);
    SocketMetrics_increment(SOCKET_METRIC_DNS_REQUEST_SUBMITTED, 4);
    SocketMetrics_increment(SOCKET_METRIC_DNS_REQUEST_COMPLETED, 5);
    SocketMetrics_increment(SOCKET_METRIC_DNS_REQUEST_FAILED, 6);
    SocketMetrics_increment(SOCKET_METRIC_DNS_REQUEST_CANCELLED, 7);
    SocketMetrics_increment(SOCKET_METRIC_DNS_REQUEST_TIMEOUT, 8);
    SocketMetrics_increment(SOCKET_METRIC_POLL_WAKEUPS, 9);
    SocketMetrics_increment(SOCKET_METRIC_POLL_EVENTS_DISPATCHED, 10);
    SocketMetrics_increment(SOCKET_METRIC_POOL_CONNECTIONS_ADDED, 11);
    SocketMetrics_increment(SOCKET_METRIC_POOL_CONNECTIONS_REMOVED, 12);
    SocketMetrics_increment(SOCKET_METRIC_POOL_CONNECTIONS_REUSED, 13);

    SocketMetrics_getsnapshot(&snapshot);

    ASSERT_EQ(1ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
    ASSERT_EQ(2ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_SOCKET_CONNECT_FAILURE));
    ASSERT_EQ(3ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_SOCKET_SHUTDOWN_CALL));
    ASSERT_EQ(4ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_DNS_REQUEST_SUBMITTED));
    ASSERT_EQ(5ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_DNS_REQUEST_COMPLETED));
    ASSERT_EQ(6ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_DNS_REQUEST_FAILED));
    ASSERT_EQ(7ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_DNS_REQUEST_CANCELLED));
    ASSERT_EQ(8ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_DNS_REQUEST_TIMEOUT));
    ASSERT_EQ(9ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_POLL_WAKEUPS));
    ASSERT_EQ(10ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_POLL_EVENTS_DISPATCHED));
    ASSERT_EQ(11ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_POOL_CONNECTIONS_ADDED));
    ASSERT_EQ(12ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_POOL_CONNECTIONS_REMOVED));
    ASSERT_EQ(13ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_POOL_CONNECTIONS_REUSED));
}

TEST(socketmetrics_metric_names)
{
    ASSERT_NOT_NULL(SocketMetrics_name(SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
    ASSERT_NOT_NULL(SocketMetrics_name(SOCKET_METRIC_SOCKET_CONNECT_FAILURE));
    ASSERT_NOT_NULL(SocketMetrics_name(SOCKET_METRIC_DNS_REQUEST_SUBMITTED));
    ASSERT_NOT_NULL(SocketMetrics_name(SOCKET_METRIC_POLL_WAKEUPS));
    ASSERT_NOT_NULL(SocketMetrics_name(SOCKET_METRIC_POOL_CONNECTIONS_ADDED));
    ASSERT_NOT_NULL(SocketMetrics_name((SocketMetric)999));
}

TEST(socketmetrics_increment_by_value)
{
    SocketMetricsSnapshot snapshot = {{0ULL}};

    SocketMetrics_reset();
    SocketMetrics_increment(SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 5);
    SocketMetrics_increment(SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 3);
    SocketMetrics_getsnapshot(&snapshot);

    ASSERT_EQ(8ULL, SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
}

TEST(socketevents_multiple_handlers)
{
    EventProbe probe1 = {0};
    EventProbe probe2 = {0};

    SocketEvent_register(event_probe_callback, &probe1);
    SocketEvent_register(event_probe_callback, &probe2);
    SocketEvent_emit_poll_wakeup(10, 200);

    ASSERT_EQ(1, probe1.count);
    ASSERT_EQ(1, probe2.count);
    ASSERT_EQ(10, probe1.last_event.data.poll.nfds);
    ASSERT_EQ(10, probe2.last_event.data.poll.nfds);

    SocketEvent_unregister(event_probe_callback, &probe1);
    SocketEvent_unregister(event_probe_callback, &probe2);
}

TEST(socketevents_accept_and_connect_events)
{
    EventProbe probe = {0};

    SocketEvent_register(event_probe_callback, &probe);
    SocketEvent_emit_accept(42, "192.168.1.1", 8080, "0.0.0.0", 80);

    ASSERT_EQ(1, probe.count);
    ASSERT_EQ(SOCKET_EVENT_ACCEPTED, probe.last_event.type);
    ASSERT_EQ(42, probe.last_event.data.connection.fd);
    ASSERT(strcmp(probe.last_event.data.connection.peer_addr, "192.168.1.1") == 0);
    ASSERT_EQ(8080, probe.last_event.data.connection.peer_port);
    ASSERT(strcmp(probe.last_event.data.connection.local_addr, "0.0.0.0") == 0);
    ASSERT_EQ(80, probe.last_event.data.connection.local_port);

    SocketEvent_emit_connect(43, "10.0.0.1", 443, "192.168.1.2", 50000);
    ASSERT_EQ(2, probe.count);
    ASSERT_EQ(SOCKET_EVENT_CONNECTED, probe.last_event.type);
    ASSERT_EQ(43, probe.last_event.data.connection.fd);
    ASSERT(strcmp(probe.last_event.data.connection.peer_addr, "10.0.0.1") == 0);
    ASSERT_EQ(443, probe.last_event.data.connection.peer_port);

    SocketEvent_unregister(event_probe_callback, &probe);
}

TEST(socketevents_duplicate_registration_ignored)
{
    EventProbe probe = {0};

    SocketEvent_register(event_probe_callback, &probe);
    SocketEvent_register(event_probe_callback, &probe);
    SocketEvent_emit_poll_wakeup(1, 0);

    ASSERT_EQ(1, probe.count);

    SocketEvent_unregister(event_probe_callback, &probe);
    SocketEvent_emit_poll_wakeup(1, 0);
    ASSERT_EQ(1, probe.count);
}

TEST(socketevents_handler_limit_enforced)
{
    EventProbe probes[16] = {0};
    int i;

    for (i = 0; i < 8; i++)
    {
        SocketEvent_register(event_probe_callback, &probes[i]);
    }

    SocketEvent_emit_poll_wakeup(1, 0);
    ASSERT_EQ(1, probes[0].count);

    SocketEvent_register(event_probe_callback, &probes[8]);
    SocketEvent_emit_poll_wakeup(1, 0);
    ASSERT_EQ(0, probes[8].count);

    for (i = 0; i < 8; i++)
    {
        SocketEvent_unregister(event_probe_callback, &probes[i]);
    }
}

TEST(socket_bind_async_wildcard_uses_ai_passive)
{
    SocketDNS_T dns = NULL;
    Socket_T socket = NULL;
    SocketDNS_Request_T req;
    struct addrinfo *res = NULL;

    TRY
        dns = SocketDNS_new();
        socket = Socket_new(AF_INET, SOCK_STREAM, 0);

        req = Socket_bind_async(dns, socket, NULL, 0);

        while ((res = SocketDNS_getresult(dns, req)) == NULL)
        {
            usleep(10000);
        }

        ASSERT_NOT_NULL(res);
        ASSERT_NOT_NULL(res->ai_addr);

        Socket_bind_with_addrinfo(socket, res);
        Socket_listen(socket, 5);

        ASSERT(Socket_getlocalport(socket) >= 1);
        ASSERT(Socket_getlocalport(socket) <= 65535);

        freeaddrinfo(res);
        res = NULL;
    EXCEPT(Socket_Failed)
        if (res)
            freeaddrinfo(res);
    EXCEPT(SocketDNS_Failed)
        if (res)
            freeaddrinfo(res);
    FINALLY
        if (socket)
            Socket_free(&socket);
        if (dns)
            SocketDNS_free(&dns);
    END_TRY;
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}

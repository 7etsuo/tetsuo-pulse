/**
 * test_integration.c - Comprehensive integration tests
 *
 * Industry-standard integration testing for the socket library.
 * Tests complete server/client scenarios with Poll, Pool, DNS integration.
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test/Test.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "pool/SocketPool.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketDgram.h"

#define TEST_BUFFER_SIZE 4096
#define TEST_PORT_BASE 40000

static Socket_T tracked_sockets[128];
static int tracked_count;

static void
reset_tracked_sockets(void)
{
    tracked_count = 0;
}

static void
track_socket(Socket_T socket)
{
    if (socket && tracked_count < (int)(sizeof(tracked_sockets) / sizeof(tracked_sockets[0])))
        tracked_sockets[tracked_count++] = socket;
}

static void
untrack_socket(Socket_T socket)
{
    for (int i = 0; i < tracked_count; i++)
    {
        if (tracked_sockets[i] == socket)
        {
            tracked_sockets[i] = tracked_sockets[tracked_count - 1];
            tracked_sockets[tracked_count - 1] = NULL;
            tracked_count--;
            return;
        }
    }
}

static void
assert_no_tracked_sockets(void)
{
    ASSERT_EQ(tracked_count, 0);
}

static void
assert_no_socket_leaks(void)
{
    ASSERT_EQ(Socket_debug_live_count(), 0);
}

static void setup_signals(void)
{
    signal(SIGPIPE, SIG_IGN);
}

/* ==================== TCP Server Integration Tests ==================== */

TEST(integration_simple_tcp_server)
{
    setup_signals();
    reset_tracked_sockets();
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(100);
    SocketPool_T pool = SocketPool_new(arena, 100, 4096);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 10);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        Socket_connect(client, "127.0.0.1", port);
        usleep(50000);
        
        SocketEvent_T *events = NULL;
        int nfds = SocketPoll_wait(poll, &events, 100);
        
        if (nfds > 0 && events[0].socket == server)
        {
            Socket_T accepted = Socket_accept(server);
            if (accepted)
            {
                Socket_T tracked = accepted;
                track_socket(tracked);
                Connection_T conn = SocketPool_add(pool, accepted);
                ASSERT_NOT_NULL(conn);
                SocketPool_remove(pool, accepted);
                Socket_free(&accepted);
                untrack_socket(tracked);
            }
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketPoll_Failed) (void)0;
    EXCEPT(SocketPool_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
        SocketPoll_free(&poll);
        if (pool)
        {
            SocketPool_cleanup(pool, 0);
            ASSERT_EQ(SocketPool_count(pool), 0);
        }
        SocketPool_free(&pool);
        Arena_dispose(&arena);
        assert_no_tracked_sockets();
        assert_no_socket_leaks();
    END_TRY;
}

TEST(integration_tcp_echo_server)
{
    setup_signals();
    reset_tracked_sockets();
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(100);
    SocketPool_T pool = SocketPool_new(arena, 100, 4096);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 10);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        Socket_connect(client, "127.0.0.1", port);
        usleep(50000);
        
        SocketEvent_T *events = NULL;
        int nfds = SocketPoll_wait(poll, &events, 100);
        
        if (nfds > 0)
        {
            Socket_T accepted = Socket_accept(server);
            if (accepted)
            {
                Socket_T tracked = accepted;
                track_socket(tracked);
                Connection_T conn = SocketPool_add(pool, accepted);
                SocketPoll_add(poll, accepted, POLL_READ, conn);
                
                const char *msg = "Echo test";
                Socket_send(client, msg, strlen(msg));
                usleep(50000);
                
                nfds = SocketPoll_wait(poll, &events, 100);
                if (nfds > 0)
                {
                    char buf[TEST_BUFFER_SIZE] = {0};
                    ssize_t received = Socket_recv(accepted, buf, sizeof(buf) - 1);
                    if (received > 0)
                    {
                        ASSERT_EQ(strcmp(buf, msg), 0);
                        Socket_send(accepted, buf, received);
                    }
                }
                
                SocketPoll_del(poll, accepted);
                SocketPool_remove(pool, accepted);
                Socket_free(&accepted);
                untrack_socket(tracked);
            }
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketPoll_Failed) (void)0;
    EXCEPT(SocketPool_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
        SocketPoll_free(&poll);
        if (pool)
        {
            SocketPool_cleanup(pool, 0);
            ASSERT_EQ(SocketPool_count(pool), 0);
        }
        SocketPool_free(&pool);
        Arena_dispose(&arena);
        assert_no_tracked_sockets();
        assert_no_socket_leaks();
    END_TRY;
}

TEST(integration_tcp_multiple_clients)
{
    setup_signals();
    reset_tracked_sockets();
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(100);
    SocketPool_T pool = SocketPool_new(arena, 100, 4096);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client1 = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client2 = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T accepted_sockets[2] = {NULL, NULL};
    volatile int accepted_count = 0;

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 10);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        
        Socket_connect(client1, "127.0.0.1", port);
        Socket_connect(client2, "127.0.0.1", port);
        usleep(100000);
        
        for (int i = 0; i < 2; i++)
        {
            SocketEvent_T *events = NULL;
            int nfds = SocketPoll_wait(poll, &events, 100);
            
            if (nfds > 0 && events[0].socket == server)
            {
                Socket_T accepted = Socket_accept(server);
                if (accepted)
                {
                    Socket_T tracked = accepted;
                    track_socket(tracked);
                    SocketPool_add(pool, accepted);
                    SocketPoll_add(poll, accepted, POLL_READ, NULL);
                    if (accepted_count < 2)
                        accepted_sockets[accepted_count++] = tracked;
                }
            }
        }
        
        size_t conn_count = SocketPool_count(pool);
        ASSERT_NE(conn_count, 0);
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketPoll_Failed) (void)0;
    EXCEPT(SocketPool_Failed) (void)0;
    FINALLY
        for (int i = 0; i < accepted_count; i++)
        {
            Socket_T sock = accepted_sockets[i];
            if (sock)
            {
                SocketPoll_del(poll, sock);
                SocketPool_remove(pool, sock);
                untrack_socket(sock);
                Socket_free(&sock);
                accepted_sockets[i] = NULL;
            }
        }
        Socket_free(&client2);
        Socket_free(&client1);
        Socket_free(&server);
        SocketPoll_free(&poll);
        if (pool)
        {
            SocketPool_cleanup(pool, 0);
            ASSERT_EQ(SocketPool_count(pool), 0);
        }
        SocketPool_free(&pool);
        Arena_dispose(&arena);
        assert_no_tracked_sockets();
        assert_no_socket_leaks();
    END_TRY;
}

/* ==================== UDP Integration Tests ==================== */

TEST(integration_udp_echo_server)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    SocketDgram_T server = SocketDgram_new(AF_INET, 0);
    SocketDgram_T client = SocketDgram_new(AF_INET, 0);

    TRY
        SocketDgram_bind(server, "127.0.0.1", 0);
        SocketDgram_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(SocketDgram_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        const char *msg = "UDP echo test";
        SocketDgram_sendto(client, msg, strlen(msg), "127.0.0.1", port);
        usleep(50000);
        
        char recv_host[256] = {0};
        int recv_port = 0;
        char buf[TEST_BUFFER_SIZE] = {0};
        ssize_t received = SocketDgram_recvfrom(server, buf, sizeof(buf) - 1, recv_host, sizeof(recv_host), &recv_port);
        
        if (received > 0)
        {
            ASSERT_EQ(strcmp(buf, msg), 0);
            SocketDgram_sendto(server, buf, received, recv_host, recv_port);
        }
    EXCEPT(SocketDgram_Failed) (void)0;
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketDgram_free(&client);
        SocketDgram_free(&server);
        SocketPoll_free(&poll);
    END_TRY;
}

/* ==================== Pool Integration Tests ==================== */

TEST(integration_pool_with_buffers)
{
    setup_signals();
    reset_tracked_sockets();
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 10, 1024);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 1);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        Socket_connect(client, "127.0.0.1", port);
        usleep(50000);
        
        Socket_T accepted = Socket_accept(server);
        if (accepted)
        {
            Socket_T tracked = accepted;
            track_socket(tracked);
            Connection_T conn = SocketPool_add(pool, accepted);
            ASSERT_NOT_NULL(conn);
            
            SocketBuf_T inbuf = Connection_inbuf(conn);
            SocketBuf_T outbuf = Connection_outbuf(conn);
            
            const char *in_msg = "Input test";
            const char *out_msg = "Output test";
            SocketBuf_write(inbuf, in_msg, strlen(in_msg));
            SocketBuf_write(outbuf, out_msg, strlen(out_msg));
            
            ASSERT_EQ(SocketBuf_available(inbuf), strlen(in_msg));
            ASSERT_EQ(SocketBuf_available(outbuf), strlen(out_msg));
            
            SocketPool_remove(pool, accepted);
            Socket_free(&accepted);
            untrack_socket(tracked);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketPool_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
        if (pool)
        {
            SocketPool_cleanup(pool, 0);
            ASSERT_EQ(SocketPool_count(pool), 0);
        }
        SocketPool_free(&pool);
        Arena_dispose(&arena);
        assert_no_tracked_sockets();
        assert_no_socket_leaks();
    END_TRY;
}

TEST(integration_pool_cleanup_idle)
{
    setup_signals();
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 10, 1024);
    volatile Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        volatile size_t count_before;
        volatile size_t count_after;
        volatile Connection_T conn;
        conn = SocketPool_add(pool, socket);
        ASSERT_NOT_NULL(conn);
        socket = NULL;  /* Ownership transferred to pool */
        
        count_before = SocketPool_count(pool);
        ASSERT_EQ(count_before, 1);
        
        sleep(2);
        SocketPool_cleanup(pool, 1);
        
        count_after = SocketPool_count(pool);
        ASSERT_EQ(count_after, 0);
    EXCEPT(SocketPool_Failed) (void)0;
    FINALLY
        if (socket)
        {
            Socket_T s = (Socket_T)socket;
            Socket_free(&s);
        }
        if (pool)
        {
            SocketPool_cleanup(pool, 0);
            ASSERT_EQ(SocketPool_count(pool), 0);
        }
        SocketPool_free(&pool);
        Arena_dispose(&arena);
        assert_no_tracked_sockets();
        assert_no_socket_leaks();
    END_TRY;
}

/* ==================== Full Stack Integration Tests ==================== */

TEST(integration_full_stack_tcp_server)
{
    setup_signals();
    reset_tracked_sockets();
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(100);
    SocketPool_T pool = SocketPool_new(arena, 100, 8192);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T accepted_sockets[32] = {NULL};
    volatile int accepted_count = 0;

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 10);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        Socket_connect(client, "127.0.0.1", port);
        usleep(50000);
        
        for (int iteration = 0; iteration < 3; iteration++)
        {
            SocketEvent_T *events = NULL;
            int nfds = SocketPoll_wait(poll, &events, 100);
            
            for (int i = 0; i < nfds; i++)
            {
                if (events[i].socket == server && (events[i].events & POLL_READ))
                {
                    Socket_T accepted = Socket_accept(server);
                    if (accepted)
                    {
                        Socket_T tracked = accepted;
                        track_socket(tracked);
                        Connection_T conn = SocketPool_add(pool, accepted);
                        if (conn)
                        {
                            SocketPoll_add(poll, accepted, POLL_READ, conn);
                            if (accepted_count < 32)
                                accepted_sockets[accepted_count++] = tracked;
                        }
                        else
                        {
                            Socket_free(&accepted);
                            untrack_socket(tracked);
                        }
                    }
                }
                else if (events[i].data && (events[i].events & POLL_READ))
                {
                    Connection_T conn = (Connection_T)events[i].data;
                    Socket_T sock = Connection_socket(conn);
                    SocketBuf_T inbuf = Connection_inbuf(conn);
                    
                    char buf[1024];
                    ssize_t received = Socket_recv(sock, buf, sizeof(buf));
                    if (received > 0)
                    {
                        SocketBuf_write(inbuf, buf, received);
                    }
                }
            }
            usleep(10000);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketPoll_Failed) (void)0;
    EXCEPT(SocketPool_Failed) (void)0;
    FINALLY
        for (int i = 0; i < accepted_count; i++)
        {
            Socket_T sock = accepted_sockets[i];
            if (sock)
            {
                SocketPoll_del(poll, sock);
                SocketPool_remove(pool, sock);
                untrack_socket(sock);
                Socket_free(&sock);
                accepted_sockets[i] = NULL;
            }
        }
        Socket_free(&client);
        Socket_free(&server);
        SocketPoll_free(&poll);
        if (pool)
        {
            SocketPool_cleanup(pool, 0);
            ASSERT_EQ(SocketPool_count(pool), 0);
        }
        SocketPool_free(&pool);
        Arena_dispose(&arena);
        assert_no_tracked_sockets();
        assert_no_socket_leaks();
    END_TRY;
}

/* ==================== Multi-threaded Server Test ==================== */

static volatile int server_running;
static int server_port;

static void *server_thread(void *arg)
{
    (void)arg;
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(100);
    SocketPool_T pool = SocketPool_new(arena, 100, 4096);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 10);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        server_port = ntohs(addr.sin_port);
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        
        while (server_running)
        {
            SocketEvent_T *events = NULL;
            int nfds = SocketPoll_wait(poll, &events, 100);
            
            for (int i = 0; i < nfds; i++)
            {
                if (events[i].socket == server)
                {
                    Socket_T accepted = Socket_accept(server);
                    if (accepted)
                    {
                        Socket_T tracked = accepted;
                        track_socket(tracked);
                        Socket_free(&accepted);
                        untrack_socket(tracked);
                    }
                }
            }
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        Socket_free(&server);
        SocketPoll_free(&poll);
        if (pool)
        {
            SocketPool_cleanup(pool, 0);
            ASSERT_EQ(SocketPool_count(pool), 0);
        }
        SocketPool_free(&pool);
        Arena_dispose(&arena);
    END_TRY;
    
    return NULL;
}

TEST(integration_multithreaded_server)
{
    setup_signals();
    reset_tracked_sockets();
    pthread_t server_tid;
    server_running = 1;
    server_port = 0;
    
    pthread_create(&server_tid, NULL, server_thread, NULL);
    usleep(200000);
    
    Socket_T clients[5];
    for (int i = 0; i < 5; i++)
    {
        clients[i] = Socket_new(AF_INET, SOCK_STREAM, 0);
        TRY Socket_connect(clients[i], "127.0.0.1", server_port);
        EXCEPT(Socket_Failed) (void)0;
        END_TRY;
        usleep(10000);
    }
    
    usleep(100000);
    server_running = 0;
    pthread_join(server_tid, NULL);
    
    for (int i = 0; i < 5; i++)
        Socket_free(&clients[i]);
    assert_no_tracked_sockets();
    assert_no_socket_leaks();
}

/* ==================== Arena Integration Tests ==================== */

TEST(integration_arena_lifecycle)
{
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 50, 2048);
    
    for (int i = 0; i < 10; i++)
    {
        Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
        Socket_T tracked = socket;
        track_socket(tracked);
        TRY
            Connection_T conn = SocketPool_add(pool, socket);
            if (conn)
            {
                SocketBuf_T inbuf = Connection_inbuf(conn);
                SocketBuf_write(inbuf, "Data", 4);
                SocketPool_remove(pool, socket);
            }
        EXCEPT(SocketPool_Failed) (void)0;
        END_TRY;
        Socket_free(&socket);
        untrack_socket(tracked);
    }
    
    if (pool)
    {
        SocketPool_cleanup(pool, 0);
        ASSERT_EQ(SocketPool_count(pool), 0);
    }
    SocketPool_free(&pool);
    Arena_dispose(&arena);
    assert_no_tracked_sockets();
    assert_no_socket_leaks();
}

/* ==================== Connection Lifecycle Tests ==================== */

TEST(integration_connection_full_lifecycle)
{
    setup_signals();
    reset_tracked_sockets();
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(100);
    SocketPool_T pool = SocketPool_new(arena, 100, 4096);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 10);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        Socket_connect(client, "127.0.0.1", port);
        usleep(50000);
        
        SocketEvent_T *events = NULL;
        int nfds = SocketPoll_wait(poll, &events, 100);
        
        if (nfds > 0)
        {
            Socket_T accepted = Socket_accept(server);
            if (accepted)
            {
                Socket_T tracked = accepted;
                track_socket(tracked);
                Connection_T conn = SocketPool_add(pool, accepted);
                SocketPoll_add(poll, accepted, POLL_READ | POLL_WRITE, conn);
                
                Connection_setdata(conn, (void *)42);
                ASSERT_EQ(Connection_data(conn), (void *)42);
                ASSERT_EQ(Connection_socket(conn), accepted);
                ASSERT_NE(Connection_isactive(conn), 0);
                
                SocketPoll_del(poll, accepted);
                SocketPool_remove(pool, accepted);
                Socket_free(&accepted);
                untrack_socket(tracked);
            }
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketPoll_Failed) (void)0;
    EXCEPT(SocketPool_Failed) (void)0;
    FINALLY
        Socket_free(&client);
        Socket_free(&server);
        SocketPoll_free(&poll);
        if (pool)
        {
            SocketPool_cleanup(pool, 0);
            ASSERT_EQ(SocketPool_count(pool), 0);
        }
        SocketPool_free(&pool);
        Arena_dispose(&arena);
        assert_no_tracked_sockets();
        assert_no_socket_leaks();
    END_TRY;
}

/* ==================== Stress Integration Tests ==================== */

TEST(integration_rapid_connect_disconnect)
{
    setup_signals();
    reset_tracked_sockets();
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(100);
    SocketPool_T pool = SocketPool_new(arena, 50, 2048);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 50);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        
        for (int i = 0; i < 10; i++)
        {
            Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
            Socket_connect(client, "127.0.0.1", port);
            usleep(20000);
            
            SocketEvent_T *events = NULL;
            int nfds = SocketPoll_wait(poll, &events, 50);
            
            if (nfds > 0)
            {
                Socket_T accepted = Socket_accept(server);
                if (accepted)
                {
                    Socket_T tracked = accepted;
                    track_socket(tracked);
                    SocketPool_add(pool, accepted);
                    SocketPool_remove(pool, accepted);
                    Socket_free(&accepted);
                    untrack_socket(tracked);
                }
            }
            Socket_free(&client);
        }
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketPoll_Failed) (void)0;
    EXCEPT(SocketPool_Failed) (void)0;
    FINALLY
        Socket_free(&server);
        SocketPoll_free(&poll);
        if (pool)
        {
            SocketPool_cleanup(pool, 0);
            ASSERT_EQ(SocketPool_count(pool), 0);
        }
        SocketPool_free(&pool);
        Arena_dispose(&arena);
        assert_no_tracked_sockets();
        assert_no_socket_leaks();
    END_TRY;
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}


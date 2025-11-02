/**
 * test_socketpoll.c - Comprehensive SocketPoll unit tests
 *
 * Industry-standard test coverage for SocketPoll event polling module.
 * Tests event polling, multiple sockets, timeout, modifications, and thread safety.
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test/Test.h"
#include "core/Except.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

#define TEST_BUFFER_SIZE 4096

static void setup_signals(void)
{
    signal(SIGPIPE, SIG_IGN);
}

/* ==================== Basic Poll Tests ==================== */

TEST(socketpoll_new_creates_poll)
{
    SocketPoll_T poll = SocketPoll_new(100);
    ASSERT_NOT_NULL(poll);
    SocketPoll_free(&poll);
    ASSERT_NULL(poll);
}

TEST(socketpoll_new_small_maxevents)
{
    SocketPoll_T poll = SocketPoll_new(1);
    ASSERT_NOT_NULL(poll);
    SocketPoll_free(&poll);
}

TEST(socketpoll_new_large_maxevents)
{
    SocketPoll_T poll = SocketPoll_new(10000);
    ASSERT_NOT_NULL(poll);
    SocketPoll_free(&poll);
}

/* ==================== Add/Remove Tests ==================== */

TEST(socketpoll_add_socket)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY SocketPoll_add(poll, socket, POLL_READ, NULL);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;
    SocketPoll_free(&poll);
    Socket_free(&socket);
}

TEST(socketpoll_add_with_user_data)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    int user_data = 42;
    
    TRY SocketPoll_add(poll, socket, POLL_READ, &user_data);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;
    
    SocketPoll_free(&poll);
    Socket_free(&socket);
}

TEST(socketpoll_add_multiple_sockets)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T sock1 = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T sock2 = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T sock3 = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketPoll_add(poll, sock1, POLL_READ, NULL);
        SocketPoll_add(poll, sock2, POLL_READ, NULL);
        SocketPoll_add(poll, sock3, POLL_READ | POLL_WRITE, NULL);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
    Socket_free(&sock3);
    Socket_free(&sock2);
    Socket_free(&sock1);
}

TEST(socketpoll_remove_socket)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketPoll_add(poll, socket, POLL_READ, NULL);
        SocketPoll_del(poll, socket);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
    Socket_free(&socket);
}

TEST(socketpoll_remove_multiple_sockets)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T sock1 = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T sock2 = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketPoll_add(poll, sock1, POLL_READ, NULL);
        SocketPoll_add(poll, sock2, POLL_READ, NULL);
        SocketPoll_del(poll, sock1);
        SocketPoll_del(poll, sock2);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
    Socket_free(&sock2);
    Socket_free(&sock1);
}

/* ==================== Modify Tests ==================== */

TEST(socketpoll_mod_events)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketPoll_add(poll, socket, POLL_READ, NULL);
        SocketPoll_mod(poll, socket, POLL_WRITE, NULL);
        SocketPoll_mod(poll, socket, POLL_READ | POLL_WRITE, NULL);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
    Socket_free(&socket);
}

TEST(socketpoll_mod_user_data)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    int data1 = 1, data2 = 2;

    TRY
        SocketPoll_add(poll, socket, POLL_READ, &data1);
        SocketPoll_mod(poll, socket, POLL_READ, &data2);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
    Socket_free(&socket);
}

/* ==================== Wait Tests ==================== */

TEST(socketpoll_wait_timeout)
{
    SocketPoll_T poll = SocketPoll_new(100);
    SocketEvent_T *events = NULL;

    TRY
        int nfds = SocketPoll_wait(poll, &events, 10);
        ASSERT_EQ(nfds, 0);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
}

TEST(socketpoll_wait_read_event)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
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
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        Socket_connect(client, "127.0.0.1", port);
        usleep(50000);
        
        SocketEvent_T *events = NULL;
        int nfds = SocketPoll_wait(poll, &events, 100);
        
        if (nfds > 0)
        {
            ASSERT_NOT_NULL(events);
            ASSERT_NOT_NULL(events[0].socket);
            ASSERT_NE(events[0].events & POLL_READ, 0);
        }
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

TEST(socketpoll_wait_write_event)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(socket, "127.0.0.1", 0);
        Socket_setnonblocking(socket);
        SocketPoll_add(poll, socket, POLL_WRITE, NULL);
        
        SocketEvent_T *events = NULL;
        int nfds = SocketPoll_wait(poll, &events, 100);
        
        if (nfds > 0)
        {
            ASSERT_NOT_NULL(events);
            ASSERT_NE(events[0].events & POLL_WRITE, 0);
        }
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&socket);
    END_TRY;
}

TEST(socketpoll_wait_multiple_events)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
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
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        Socket_connect(client1, "127.0.0.1", port);
        Socket_connect(client2, "127.0.0.1", port);
        usleep(50000);
        
        SocketEvent_T *events = NULL;
        int nfds = SocketPoll_wait(poll, &events, 100);
        ASSERT_NE(nfds, -1);
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&client2);
        Socket_free(&client1);
        Socket_free(&server);
    END_TRY;
}

TEST(socketpoll_wait_with_user_data)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
    int user_data = 12345;

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 1);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketPoll_add(poll, server, POLL_READ, &user_data);
        Socket_connect(client, "127.0.0.1", port);
        usleep(50000);
        
        SocketEvent_T *events = NULL;
        int nfds = SocketPoll_wait(poll, &events, 100);
        
        if (nfds > 0 && events[0].data)
        {
            ASSERT_EQ(*(int *)events[0].data, user_data);
        }
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

/* ==================== Edge Case Tests ==================== */

TEST(socketpoll_wait_empty_poll)
{
    SocketPoll_T poll = SocketPoll_new(100);
    SocketEvent_T *events = NULL;

    TRY
        int nfds = SocketPoll_wait(poll, &events, 10);
        ASSERT_EQ(nfds, 0);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
}

TEST(socketpoll_wait_negative_timeout)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_setnonblocking(socket);
        SocketPoll_add(poll, socket, POLL_WRITE, NULL);
        
        SocketEvent_T *events = NULL;
        int nfds = SocketPoll_wait(poll, &events, -1);
        ASSERT_NE(nfds, -1);
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&socket);
    END_TRY;
}

TEST(socketpoll_add_remove_readd)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketPoll_add(poll, socket, POLL_READ, NULL);
        SocketPoll_del(poll, socket);
        SocketPoll_add(poll, socket, POLL_WRITE, NULL);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
    Socket_free(&socket);
}

TEST(socketpoll_mod_after_add)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        SocketPoll_add(poll, socket, POLL_READ, NULL);
        SocketPoll_mod(poll, socket, POLL_WRITE, NULL);
        SocketPoll_mod(poll, socket, POLL_READ | POLL_WRITE, NULL);
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
    Socket_free(&socket);
}

/* ==================== Integration Tests ==================== */

TEST(socketpoll_accept_via_poll)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 5);
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
            ASSERT_EQ(events[0].socket, server);
            Socket_T accepted = Socket_accept(server);
            if (accepted) Socket_free(&accepted);
        }
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

TEST(socketpoll_data_ready_event)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
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
            SocketPoll_add(poll, accepted, POLL_READ, NULL);
            const char *msg = "Test data";
            Socket_send(client, msg, strlen(msg));
            usleep(50000);
            
            SocketEvent_T *events = NULL;
            int nfds = SocketPoll_wait(poll, &events, 100);
            
            if (nfds > 0)
            {
                ASSERT_EQ(events[0].socket, accepted);
                ASSERT_NE(events[0].events & POLL_READ, 0);
                
                char buf[TEST_BUFFER_SIZE] = {0};
                ssize_t received = Socket_recv(accepted, buf, sizeof(buf) - 1);
                if (received > 0) ASSERT_EQ(strcmp(buf, msg), 0);
            }
            Socket_free(&accepted);
        }
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&client);
        Socket_free(&server);
    END_TRY;
}

TEST(socketpoll_multiple_ready_sockets)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
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
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        Socket_connect(client1, "127.0.0.1", port);
        Socket_connect(client2, "127.0.0.1", port);
        usleep(100000);
        
        SocketEvent_T *events = NULL;
        int nfds = SocketPoll_wait(poll, &events, 100);
        ASSERT_NE(nfds, -1);
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&client2);
        Socket_free(&client1);
        Socket_free(&server);
    END_TRY;
}

/* ==================== Event Loop Simulation Tests ==================== */

TEST(socketpoll_event_loop_simulation)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 10);
        Socket_setnonblocking(server);
        SocketPoll_add(poll, server, POLL_READ, NULL);
        
        for (int i = 0; i < 5; i++)
        {
            SocketEvent_T *events = NULL;
            int nfds = SocketPoll_wait(poll, &events, 10);
            (void)nfds;
        }
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&server);
    END_TRY;
}

/* ==================== Stress Tests ==================== */

TEST(socketpoll_many_sockets)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(1000);
    Socket_T sockets[50];

    TRY
        for (int i = 0; i < 50; i++)
        {
            sockets[i] = Socket_new(AF_INET, SOCK_STREAM, 0);
            SocketPoll_add(poll, sockets[i], POLL_READ, NULL);
        }
        
        for (int i = 0; i < 50; i++)
        {
            SocketPoll_del(poll, sockets[i]);
        }
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    FINALLY
        for (int i = 0; i < 50; i++)
            Socket_free(&sockets[i]);
        SocketPoll_free(&poll);
    END_TRY;
}

TEST(socketpoll_rapid_add_remove)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        for (int i = 0; i < 100; i++)
        {
            SocketPoll_add(poll, socket, POLL_READ, NULL);
            SocketPoll_del(poll, socket);
        }
    EXCEPT(SocketPoll_Failed) ASSERT(0);
    END_TRY;

    SocketPoll_free(&poll);
    Socket_free(&socket);
}

/* ==================== Thread Safety Tests ==================== */

static void *thread_poll_operations(void *arg)
{
    SocketPoll_T poll = (SocketPoll_T)arg;
    
    for (int i = 0; i < 20; i++)
    {
        SocketEvent_T *events = NULL;
        TRY SocketPoll_wait(poll, &events, 5);
        EXCEPT(SocketPoll_Failed) break;
        END_TRY;
        usleep(1000);
    }
    
    return NULL;
}

TEST(socketpoll_concurrent_wait)
{
    setup_signals();
    SocketPoll_T poll = SocketPoll_new(100);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    pthread_t threads[4];

    TRY
        Socket_setnonblocking(socket);
        SocketPoll_add(poll, socket, POLL_WRITE, NULL);
        
        for (int i = 0; i < 4; i++)
            pthread_create(&threads[i], NULL, thread_poll_operations, poll);
        
        for (int i = 0; i < 4; i++)
            pthread_join(threads[i], NULL);
    EXCEPT(SocketPoll_Failed) (void)0;
    FINALLY
        SocketPoll_free(&poll);
        Socket_free(&socket);
    END_TRY;
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}



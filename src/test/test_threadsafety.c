/**
 * test_threadsafety.c - Thread safety and concurrency stress tests
 *
 * Industry-standard concurrency testing for the socket library.
 * Tests thread safety of all modules under heavy concurrent load.
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

#define NUM_THREADS 8
#define OPERATIONS_PER_THREAD 100

static void setup_signals(void)
{
    signal(SIGPIPE, SIG_IGN);
}

/* ==================== Arena Thread Safety Tests ==================== */

static void *thread_arena_operations(void *arg)
{
    Arena_T arena = (Arena_T)arg;
    
    for (int i = 0; i < OPERATIONS_PER_THREAD; i++)
    {
        TRY
            void *ptr1 = ALLOC(arena, 100);
            void *ptr2 = ALLOC(arena, 200);
            void *ptr3 = CALLOC(arena, 10, sizeof(int));
            (void)ptr1; (void)ptr2; (void)ptr3;
        EXCEPT(Arena_Failed) break;
        END_TRY;
    }
    
    return NULL;
}

TEST(threadsafety_arena_concurrent_alloc)
{
    Arena_T arena = Arena_new();
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_arena_operations, arena);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    Arena_dispose(&arena);
}

static void *thread_arena_clear(void *arg)
{
    Arena_T arena = (Arena_T)arg;
    
    for (int i = 0; i < 50; i++)
    {
        TRY
            ALLOC(arena, 500);
            if (i % 10 == 0) Arena_clear(arena);
        EXCEPT(Arena_Failed) break;
        END_TRY;
        usleep(100);
    }
    
    return NULL;
}

TEST(threadsafety_arena_concurrent_clear)
{
    Arena_T arena = Arena_new();
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_arena_clear, arena);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    Arena_dispose(&arena);
}

/* ==================== Exception Thread Safety Tests ==================== */

static const Except_T ThreadTest_Exception = {"Thread test exception"};

static void *thread_exception_handling(void *arg)
{
    (void)arg;
    
    for (int i = 0; i < OPERATIONS_PER_THREAD; i++)
    {
        TRY
            if (i % 2 == 0)
                RAISE(ThreadTest_Exception);
        EXCEPT(ThreadTest_Exception)
            /* Exception caught successfully */
            (void)0;
        END_TRY;
    }
    
    return NULL;
}

TEST(threadsafety_exception_concurrent_raising)
{
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_exception_handling, NULL);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
}

/* ==================== Socket Thread Safety Tests ==================== */

static void *thread_socket_operations(void *arg)
{
    (void)arg;
    setup_signals();
    
    for (int i = 0; i < 50; i++)
    {
        Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
        TRY
            Socket_setnonblocking(socket);
            Socket_setreuseaddr(socket);
            Socket_settimeout(socket, 5);
        EXCEPT(Socket_Failed) (void)0;
        END_TRY;
        Socket_free(&socket);
    }
    
    return NULL;
}

TEST(threadsafety_socket_concurrent_operations)
{
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_socket_operations, NULL);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
}

/* ==================== SocketBuf Thread Safety Tests ==================== */

typedef struct {
    Arena_T arena;
    SocketBuf_T buf;
} BufTestData;

static void *thread_buf_writer(void *arg)
{
    SocketBuf_T buf = ((BufTestData *)arg)->buf;
    
    for (int i = 0; i < 100; i++)
    {
        char data[32];
        snprintf(data, sizeof(data), "Thread data %d", i);
        SocketBuf_write(buf, data, strlen(data));
        usleep(100);
    }
    
    return NULL;
}

static void *thread_buf_reader(void *arg)
{
    SocketBuf_T buf = ((BufTestData *)arg)->buf;
    
    for (int i = 0; i < 100; i++)
    {
        char data[128];
        SocketBuf_read(buf, data, sizeof(data));
        usleep(100);
    }
    
    return NULL;
}

TEST(threadsafety_socketbuf_concurrent_read_write)
{
    Arena_T arena = Arena_new();
    SocketBuf_T buf = SocketBuf_new(arena, 65536);
    BufTestData data = {arena, buf};
    pthread_t writers[4], readers[4];
    
    for (int i = 0; i < 4; i++)
    {
        pthread_create(&writers[i], NULL, thread_buf_writer, &data);
        pthread_create(&readers[i], NULL, thread_buf_reader, &data);
    }
    
    for (int i = 0; i < 4; i++)
    {
        pthread_join(writers[i], NULL);
        pthread_join(readers[i], NULL);
    }
    
    Arena_dispose(&arena);
}

/* ==================== SocketPoll Thread Safety Tests ==================== */

static void *thread_poll_add_remove(void *arg)
{
    SocketPoll_T poll = (SocketPoll_T)arg;
    setup_signals();
    
    for (int i = 0; i < 50; i++)
    {
        Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
        TRY
            SocketPoll_add(poll, socket, POLL_READ, NULL);
            usleep(100);
            SocketPoll_del(poll, socket);
        EXCEPT(SocketPoll_Failed) (void)0;
        END_TRY;
        Socket_free(&socket);
    }
    
    return NULL;
}

TEST(threadsafety_socketpoll_concurrent_add_remove)
{
    SocketPoll_T poll = SocketPoll_new(1000);
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_poll_add_remove, poll);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    SocketPoll_free(&poll);
}

/* ==================== SocketPool Thread Safety Tests ==================== */

static void *thread_pool_add_remove(void *arg)
{
    SocketPool_T pool = (SocketPool_T)arg;
    setup_signals();
    
    for (int i = 0; i < 50; i++)
    {
        Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
        TRY
            Connection_T conn = SocketPool_add(pool, socket);
            if (conn)
            {
                usleep(100);
                SocketPool_remove(pool, socket);
            }
        EXCEPT(SocketPool_Failed) (void)0;
        END_TRY;
        Socket_free(&socket);
    }
    
    return NULL;
}

TEST(threadsafety_socketpool_concurrent_add_remove)
{
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 500, 2048);
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_pool_add_remove, pool);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    SocketPool_free(&pool);
    Arena_dispose(&arena);
}

static void *thread_pool_get_operations(void *arg)
{
    SocketPool_T pool = (SocketPool_T)arg;
    setup_signals();
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    TRY
        Connection_T conn = SocketPool_add(pool, socket);
        if (conn)
        {
            for (int i = 0; i < 200; i++)
            {
                Connection_T c = SocketPool_get(pool, socket);
                (void)c;
                usleep(10);
            }
            SocketPool_remove(pool, socket);
        }
    EXCEPT(SocketPool_Failed) (void)0;
    END_TRY;
    
    Socket_free(&socket);
    return NULL;
}

TEST(threadsafety_socketpool_concurrent_get)
{
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 500, 2048);
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_pool_get_operations, pool);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    SocketPool_free(&pool);
    Arena_dispose(&arena);
}

static void *thread_pool_count(void *arg)
{
    SocketPool_T pool = (SocketPool_T)arg;
    
    for (int i = 0; i < 200; i++)
    {
        size_t count = SocketPool_count(pool);
        (void)count;
        usleep(10);
    }
    
    return NULL;
}

TEST(threadsafety_socketpool_concurrent_count)
{
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 100, 2048);
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_pool_count, pool);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    SocketPool_free(&pool);
    Arena_dispose(&arena);
}

/* ==================== SocketDNS Thread Safety Tests ==================== */

static void *thread_dns_resolve(void *arg)
{
    SocketDNS_T dns = (SocketDNS_T)arg;
    
    for (int i = 0; i < 30; i++)
    {
        TRY
            SocketDNS_Request_T req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
            (void)req;
            usleep(5000);
        EXCEPT(SocketDNS_Failed) break;
        END_TRY;
    }
    
    return NULL;
}

TEST(threadsafety_socketdns_concurrent_resolve)
{
    SocketDNS_T dns = SocketDNS_new();
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_dns_resolve, dns);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    usleep(500000);
    SocketDNS_check(dns);
    SocketDNS_free(&dns);
}

static void *thread_dns_cancel(void *arg)
{
    SocketDNS_T dns = (SocketDNS_T)arg;
    
    for (int i = 0; i < 30; i++)
    {
        TRY
            SocketDNS_Request_T req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
            usleep(1000);
            SocketDNS_cancel(dns, req);
        EXCEPT(SocketDNS_Failed) break;
        END_TRY;
    }
    
    return NULL;
}

TEST(threadsafety_socketdns_concurrent_cancel)
{
    SocketDNS_T dns = SocketDNS_new();
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_dns_cancel, dns);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    SocketDNS_free(&dns);
}

static void *thread_dns_check(void *arg)
{
    SocketDNS_T dns = (SocketDNS_T)arg;
    
    for (int i = 0; i < 100; i++)
    {
        SocketDNS_check(dns);
        usleep(5000);
    }
    
    return NULL;
}

TEST(threadsafety_socketdns_concurrent_check)
{
    SocketDNS_T dns = SocketDNS_new();
    pthread_t threads[NUM_THREADS];
    
    TRY
        for (int i = 0; i < 20; i++)
            SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
    EXCEPT(SocketDNS_Failed) (void)0;
    END_TRY;
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_dns_check, dns);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    SocketDNS_free(&dns);
}

/* ==================== Mixed Operations Thread Safety Tests ==================== */

typedef struct {
    SocketPoll_T poll;
    SocketPool_T pool;
} MixedTestData;

static void *thread_mixed_operations(void *arg)
{
    MixedTestData *data = (MixedTestData *)arg;
    setup_signals();
    
    for (int i = 0; i < 20; i++)
    {
        Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
        
        TRY
            SocketPoll_add(data->poll, socket, POLL_READ, NULL);
            Connection_T conn = SocketPool_add(data->pool, socket);
            
            usleep(100);
            
            if (conn)
            {
                SocketBuf_T inbuf = Connection_inbuf(conn);
                SocketBuf_write(inbuf, "Test", 4);
            }
            
            SocketPoll_del(data->poll, socket);
            SocketPool_remove(data->pool, socket);
        EXCEPT(SocketPoll_Failed) (void)0;
        EXCEPT(SocketPool_Failed) (void)0;
        END_TRY;
        
        Socket_free(&socket);
    }
    
    return NULL;
}

TEST(threadsafety_mixed_poll_pool_operations)
{
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(1000);
    SocketPool_T pool = SocketPool_new(arena, 500, 2048);
    MixedTestData data = {poll, pool};
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_mixed_operations, &data);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    SocketPoll_free(&poll);
    SocketPool_free(&pool);
    Arena_dispose(&arena);
}

/* ==================== Stress Tests with Exceptions ==================== */

static void *thread_exception_stress(void *arg)
{
    Arena_T arena = (Arena_T)arg;
    setup_signals();
    
    for (int i = 0; i < 50; i++)
    {
        Socket_T socket = NULL;
        
        TRY
            socket = Socket_new(AF_INET, SOCK_STREAM, 0);
            void *ptr = ALLOC(arena, 100);
            (void)ptr;
            
            Socket_setnonblocking(socket);
            
            if (i % 3 == 0)
                RAISE(ThreadTest_Exception);
        EXCEPT(ThreadTest_Exception)
            /* Cleanup in exception path */
            if (socket) Socket_free(&socket);
        EXCEPT(Socket_Failed)
            if (socket) Socket_free(&socket);
        FINALLY
            /* Additional cleanup */
            (void)0;
        END_TRY;
        
        if (socket) Socket_free(&socket);
    }
    
    return NULL;
}

TEST(threadsafety_exception_with_cleanup)
{
    Arena_T arena = Arena_new();
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_exception_stress, arena);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    
    Arena_dispose(&arena);
}

/* ==================== UDP Thread Safety Tests ==================== */

static void *thread_udp_operations(void *arg)
{
    (void)arg;
    setup_signals();
    
    for (int i = 0; i < 50; i++)
    {
        SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
        TRY
            SocketDgram_setnonblocking(socket);
            SocketDgram_setreuseaddr(socket);
            SocketDgram_setttl(socket, 64);
        EXCEPT(SocketDgram_Failed) (void)0;
        END_TRY;
        SocketDgram_free(&socket);
    }
    
    return NULL;
}

TEST(threadsafety_socketdgram_concurrent_operations)
{
    pthread_t threads[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_udp_operations, NULL);
    
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
}

/* ==================== High Load Stress Tests ==================== */

TEST(threadsafety_high_load_server_simulation)
{
    setup_signals();
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(1000);
    SocketPool_T pool = SocketPool_new(arena, 500, 4096);
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, "127.0.0.1", 0);
        Socket_listen(server, 100);
        Socket_setnonblocking(server);
        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(Socket_fd(server), (struct sockaddr *)&addr, &len);
        int port = ntohs(addr.sin_port);
        
        SocketPoll_add(poll, server, POLL_READ, NULL);
        
        Socket_T clients[20];
        for (int i = 0; i < 20; i++)
        {
            clients[i] = Socket_new(AF_INET, SOCK_STREAM, 0);
            Socket_connect(clients[i], "127.0.0.1", port);
        }
        
        usleep(200000);
        
        for (int iteration = 0; iteration < 5; iteration++)
        {
            SocketEvent_T *events = NULL;
            int nfds = SocketPoll_wait(poll, &events, 50);
            
            for (int i = 0; i < nfds; i++)
            {
                if (events[i].socket == server)
                {
                    Socket_T accepted = Socket_accept(server);
                    if (accepted)
                    {
                        SocketPool_add(pool, accepted);
                        Socket_free(&accepted);
                    }
                }
            }
        }
        
        for (int i = 0; i < 20; i++)
            Socket_free(&clients[i]);
    EXCEPT(Socket_Failed) (void)0;
    EXCEPT(SocketPoll_Failed) (void)0;
    EXCEPT(SocketPool_Failed) (void)0;
    FINALLY
        Socket_free(&server);
        SocketPoll_free(&poll);
        SocketPool_free(&pool);
        Arena_dispose(&arena);
    END_TRY;
}

/* ==================== Memory Stress Tests ==================== */

TEST(threadsafety_memory_intensive_operations)
{
    Arena_T arenas[10];
    
    for (int i = 0; i < 10; i++)
        arenas[i] = Arena_new();
    
    for (int iter = 0; iter < 5; iter++)
    {
        for (int i = 0; i < 10; i++)
        {
            TRY
                for (int j = 0; j < 100; j++)
                    ALLOC(arenas[i], 1000);
                Arena_clear(arenas[i]);
            EXCEPT(Arena_Failed) (void)0;
            END_TRY;
        }
    }
    
    for (int i = 0; i < 10; i++)
        Arena_dispose(&arenas[i]);
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}


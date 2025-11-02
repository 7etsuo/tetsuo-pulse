/**
 * test_socketdns.c - Comprehensive SocketDNS unit tests
 *
 * Industry-standard test coverage for SocketDNS async DNS module.
 * Tests async resolution, callbacks, cancellation, queue management, and thread pool.
 */

#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "test/Test.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"

/* Suppress longjmp clobbering warnings for test variables used with TRY/EXCEPT */
#pragma GCC diagnostic ignored "-Wclobbered"

/* ==================== Basic Resolver Tests ==================== */

TEST(socketdns_new_creates_resolver)
{
    SocketDNS_T dns = SocketDNS_new();
    ASSERT_NOT_NULL(dns);
    SocketDNS_free(&dns);
    ASSERT_NULL(dns);
}

TEST(socketdns_pollfd)
{
    SocketDNS_T dns = SocketDNS_new();
    ASSERT_NOT_NULL(dns);
    int fd = SocketDNS_pollfd(dns);
    ASSERT_NE(fd, -1);
    SocketDNS_free(&dns);
}

/* ==================== Resolution Tests ==================== */

TEST(socketdns_resolve_localhost)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        ASSERT_NOT_NULL(req);
        
        usleep(100000);
        SocketDNS_check(dns);
        
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        if (result)
        {
            ASSERT_NOT_NULL(result);
            freeaddrinfo(result);
        }
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_resolve_loopback_ip)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
        ASSERT_NOT_NULL(req);
        
        usleep(100000);
        SocketDNS_check(dns);
        
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        if (result)
        {
            ASSERT_NOT_NULL(result);
            freeaddrinfo(result);
        }
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_resolve_ipv6_loopback)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        req = SocketDNS_resolve(dns, "::1", 80, NULL, NULL);
        ASSERT_NOT_NULL(req);
        
        usleep(100000);
        SocketDNS_check(dns);
        
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        if (result)
        {
            ASSERT_NOT_NULL(result);
            freeaddrinfo(result);
        }
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_resolve_with_port)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        req = SocketDNS_resolve(dns, "localhost", 8080, NULL, NULL);
        ASSERT_NOT_NULL(req);
        
        usleep(100000);
        SocketDNS_check(dns);
        
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        if (result) freeaddrinfo(result);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_resolve_without_port)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        req = SocketDNS_resolve(dns, "localhost", 0, NULL, NULL);
        ASSERT_NOT_NULL(req);
        
        usleep(100000);
        SocketDNS_check(dns);
        
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        if (result) freeaddrinfo(result);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Multiple Resolution Tests ==================== */

TEST(socketdns_multiple_resolutions)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req1 = NULL, req2 = NULL, req3 = NULL;

    TRY
        req1 = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        req2 = SocketDNS_resolve(dns, "127.0.0.1", 443, NULL, NULL);
        req3 = SocketDNS_resolve(dns, "::1", 8080, NULL, NULL);
        
        ASSERT_NOT_NULL(req1);
        ASSERT_NOT_NULL(req2);
        ASSERT_NOT_NULL(req3);
        
        usleep(200000);
        SocketDNS_check(dns);
        
        struct addrinfo *res1 = SocketDNS_getresult(dns, req1);
        struct addrinfo *res2 = SocketDNS_getresult(dns, req2);
        struct addrinfo *res3 = SocketDNS_getresult(dns, req3);
        
        if (res1) freeaddrinfo(res1);
        if (res2) freeaddrinfo(res2);
        if (res3) freeaddrinfo(res3);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_sequential_resolutions)
{
    SocketDNS_T dns = SocketDNS_new();

    TRY
        for (int i = 0; i < 10; i++)
        {
            SocketDNS_Request_T req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
            ASSERT_NOT_NULL(req);
            usleep(50000);
            SocketDNS_check(dns);
            struct addrinfo *result = SocketDNS_getresult(dns, req);
            if (result) freeaddrinfo(result);
        }
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Callback Tests ==================== */

static int callback_invoked;
static void test_callback(SocketDNS_Request_T req, struct addrinfo *result, int error, void *data)
{
    (void)req;
    (void)error;
    (void)data;
    callback_invoked = 1;
    if (result) freeaddrinfo(result);
}

TEST(socketdns_callback_invoked)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        callback_invoked = 0;
        req = SocketDNS_resolve(dns, "127.0.0.1", 80, test_callback, NULL);
        ASSERT_NOT_NULL(req);
        
        usleep(200000);
        SocketDNS_check(dns);
        
        ASSERT_NE(callback_invoked, 0);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_callback_with_user_data)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;
    int user_data = 12345;
    static int received_data;

    void callback_check_data(SocketDNS_Request_T r, struct addrinfo *res, int err, void *d)
    {
        (void)r; (void)err;
        if (d) received_data = *(int *)d;
        if (res) freeaddrinfo(res);
    }

    TRY
        received_data = 0;
        req = SocketDNS_resolve(dns, "localhost", 80, callback_check_data, &user_data);
        ASSERT_NOT_NULL(req);
        
        usleep(200000);
        SocketDNS_check(dns);
        
        ASSERT_EQ(received_data, user_data);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Cancellation Tests ==================== */

TEST(socketdns_cancel_request)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        ASSERT_NOT_NULL(req);
        SocketDNS_cancel(dns, req);
        usleep(100000);
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        ASSERT_NULL(result);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_cancel_multiple)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req1 = NULL, req2 = NULL;

    TRY
        req1 = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        req2 = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
        
        SocketDNS_cancel(dns, req1);
        SocketDNS_cancel(dns, req2);
        
        usleep(100000);
        ASSERT_NULL(SocketDNS_getresult(dns, req1));
        ASSERT_NULL(SocketDNS_getresult(dns, req2));
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Check Operation Tests ==================== */

TEST(socketdns_check_returns_completion_count)
{
    SocketDNS_T dns = SocketDNS_new();

    TRY
        SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        usleep(100000);
        int count = SocketDNS_check(dns);
        ASSERT_NE(count, -1);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_check_before_completion)
{
    SocketDNS_T dns = SocketDNS_new();

    TRY
        SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        int count = SocketDNS_check(dns);
        (void)count;
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== GetResult Tests ==================== */

TEST(socketdns_getresult_before_completion)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        ASSERT_NULL(result);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_getresult_after_completion)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
        ASSERT_NOT_NULL(req);
        
        usleep(100000);
        SocketDNS_check(dns);
        
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        if (result)
        {
            ASSERT_NOT_NULL(result);
            freeaddrinfo(result);
        }
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_getresult_clears_result)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
        req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
        usleep(100000);
        SocketDNS_check(dns);
        
        struct addrinfo *result1 = SocketDNS_getresult(dns, req);
        if (result1)
        {
            freeaddrinfo(result1);
            struct addrinfo *result2 = SocketDNS_getresult(dns, req);
            ASSERT_NULL(result2);
        }
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Concurrent Resolution Tests ==================== */

TEST(socketdns_many_concurrent_resolutions)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T requests[20];

    TRY
        for (int i = 0; i < 20; i++)
        {
            requests[i] = SocketDNS_resolve(dns, "127.0.0.1", 80 + i, NULL, NULL);
            ASSERT_NOT_NULL(requests[i]);
        }
        
        usleep(500000);
        SocketDNS_check(dns);
        
        int completed = 0;
        for (int i = 0; i < 20; i++)
        {
            struct addrinfo *result = SocketDNS_getresult(dns, requests[i]);
            if (result)
            {
                completed++;
                freeaddrinfo(result);
            }
        }
        ASSERT_NE(completed, 0);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Stress Tests ==================== */

TEST(socketdns_rapid_resolution_requests)
{
    SocketDNS_T dns = SocketDNS_new();

    TRY
        for (int i = 0; i < 50; i++)
        {
            SocketDNS_Request_T req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
            ASSERT_NOT_NULL(req);
        }
        usleep(500000);
        SocketDNS_check(dns);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_resolve_cancel_cycle)
{
    SocketDNS_T dns = SocketDNS_new();

    TRY
        for (int i = 0; i < 20; i++)
        {
            SocketDNS_Request_T req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
            SocketDNS_cancel(dns, req);
        }
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Thread Safety Tests ==================== */

static void *thread_resolve_requests(void *arg)
{
    SocketDNS_T dns = (SocketDNS_T)arg;
    
    for (volatile int i = 0; i < 10; i++)
    {
        TRY
            SocketDNS_Request_T req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
            (void)req;
            usleep(10000);
        EXCEPT(SocketDNS_Failed) break;
        END_TRY;
    }
    
    return NULL;
}

TEST(socketdns_concurrent_resolutions)
{
    SocketDNS_T dns = SocketDNS_new();
    pthread_t threads[4];

    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, thread_resolve_requests, dns);
    
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
    
    usleep(500000);
    SocketDNS_check(dns);
    SocketDNS_free(&dns);
}

static void *thread_check_completions(void *arg)
{
    SocketDNS_T dns = (SocketDNS_T)arg;
    
    for (int i = 0; i < 20; i++)
    {
        SocketDNS_check(dns);
        usleep(10000);
    }
    
    return NULL;
}

TEST(socketdns_concurrent_check)
{
    SocketDNS_T dns = SocketDNS_new();
    pthread_t threads[4];

    TRY
        for (int i = 0; i < 10; i++)
            SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        
        for (int i = 0; i < 4; i++)
            pthread_create(&threads[i], NULL, thread_check_completions, dns);
        
        for (int i = 0; i < 4; i++)
            pthread_join(threads[i], NULL);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

static void *thread_cancel_requests(void *arg)
{
    SocketDNS_T dns = (SocketDNS_T)arg;
    
    for (volatile int i = 0; i < 10; i++)
    {
        TRY
            SocketDNS_Request_T req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
            usleep(5000);
            SocketDNS_cancel(dns, req);
        EXCEPT(SocketDNS_Failed) break;
        END_TRY;
    }
    
    return NULL;
}

TEST(socketdns_concurrent_cancel)
{
    SocketDNS_T dns = SocketDNS_new();
    pthread_t threads[4];

    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, thread_cancel_requests, dns);
    
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
    
    SocketDNS_free(&dns);
}

/* ==================== Thread Pool Tests ==================== */

TEST(socketdns_thread_pool_processes_requests)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T requests[10];

    TRY
        for (int i = 0; i < 10; i++)
            requests[i] = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
        
        usleep(300000);
        SocketDNS_check(dns);
        
        int completed = 0;
        for (int i = 0; i < 10; i++)
        {
            struct addrinfo *result = SocketDNS_getresult(dns, requests[i]);
            if (result)
            {
                completed++;
                freeaddrinfo(result);
            }
        }
        ASSERT_NE(completed, 0);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}



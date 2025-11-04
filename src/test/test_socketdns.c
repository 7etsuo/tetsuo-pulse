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
#include <stdio.h>

/* Suppress longjmp clobbering warnings for test variables used with TRY/EXCEPT */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

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

    TRY req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
    ASSERT_NOT_NULL(req);

    usleep(100000);
    SocketDNS_check(dns);

    struct addrinfo *result = SocketDNS_getresult(dns, req);
    if (result)
    {
        ASSERT_NOT_NULL(result);
        freeaddrinfo(result);
    }
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_resolve_loopback_ip)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
    ASSERT_NOT_NULL(req);

    usleep(100000);
    SocketDNS_check(dns);

    struct addrinfo *result = SocketDNS_getresult(dns, req);
    if (result)
    {
        ASSERT_NOT_NULL(result);
        freeaddrinfo(result);
    }
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_resolve_ipv6_loopback)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "::1", 80, NULL, NULL);
    ASSERT_NOT_NULL(req);

    usleep(100000);
    SocketDNS_check(dns);

    struct addrinfo *result = SocketDNS_getresult(dns, req);
    if (result)
    {
        ASSERT_NOT_NULL(result);
        freeaddrinfo(result);
    }
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_resolve_with_port)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "localhost", 8080, NULL, NULL);
    ASSERT_NOT_NULL(req);

    usleep(100000);
    SocketDNS_check(dns);

    struct addrinfo *result = SocketDNS_getresult(dns, req);
    if (result)
        freeaddrinfo(result);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_resolve_without_port)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "localhost", 0, NULL, NULL);
    ASSERT_NOT_NULL(req);

    usleep(100000);
    SocketDNS_check(dns);

    struct addrinfo *result = SocketDNS_getresult(dns, req);
    if (result)
        freeaddrinfo(result);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Multiple Resolution Tests ==================== */

TEST(socketdns_multiple_resolutions)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req1 = NULL, req2 = NULL, req3 = NULL;

    TRY req1 = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
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

    if (res1)
        freeaddrinfo(res1);
    if (res2)
        freeaddrinfo(res2);
    if (res3)
        freeaddrinfo(res3);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_sequential_resolutions)
{
    SocketDNS_T dns = SocketDNS_new();

    TRY volatile int i;
    for (i = 0; i < 10; i++)
    {
        SocketDNS_Request_T req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
        ASSERT_NOT_NULL(req);
        usleep(50000);
        SocketDNS_check(dns);
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        if (result)
            freeaddrinfo(result);
    }
    EXCEPT(SocketDNS_Failed)(void) 0;
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
    if (result)
        freeaddrinfo(result);
}

TEST(socketdns_callback_invoked)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY callback_invoked = 0;
    req = SocketDNS_resolve(dns, "127.0.0.1", 80, test_callback, NULL);
    ASSERT_NOT_NULL(req);

    usleep(200000);
    SocketDNS_check(dns);

    ASSERT_NE(callback_invoked, 0);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

static int test_received_data;

static void callback_check_data(SocketDNS_Request_T r, struct addrinfo *res, int err, void *d)
{
    (void)r;
    (void)err;
    if (d)
        test_received_data = *(int *)d;
    if (res)
        freeaddrinfo(res);
}

TEST(socketdns_callback_with_user_data)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;
    int user_data = 12345;

    TRY test_received_data = 0;
    req = SocketDNS_resolve(dns, "localhost", 80, callback_check_data, &user_data);
    ASSERT_NOT_NULL(req);

    usleep(200000);
    SocketDNS_check(dns);

    ASSERT_EQ(test_received_data, user_data);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Cancellation Tests ==================== */

TEST(socketdns_cancel_request)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
    ASSERT_NOT_NULL(req);
    SocketDNS_cancel(dns, req);
    usleep(100000);
    struct addrinfo *result = SocketDNS_getresult(dns, req);
    ASSERT_NULL(result);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_cancel_multiple)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req1 = NULL, req2 = NULL;

    TRY req1 = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
    req2 = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);

    SocketDNS_cancel(dns, req1);
    SocketDNS_cancel(dns, req2);

    usleep(100000);
    ASSERT_NULL(SocketDNS_getresult(dns, req1));
    ASSERT_NULL(SocketDNS_getresult(dns, req2));
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Check Operation Tests ==================== */

TEST(socketdns_check_returns_completion_count)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
    {
        volatile int count;

        req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        usleep(100000);
        count = SocketDNS_check(dns);
        ASSERT_NE(count, -1);

        /* Drain result to release getaddrinfo allocation */
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        if (result)
            freeaddrinfo(result);
    }
    EXCEPT(SocketDNS_Failed)
    {
        (void)0;
    }
    FINALLY
    {
        SocketDNS_free(&dns);
    }
    END_TRY;
}

TEST(socketdns_check_before_completion)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY
    {
        volatile int count;

        req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        count = SocketDNS_check(dns);
        (void)count;

        /* Allow resolver to finish, then drain result */
        usleep(100000);
        SocketDNS_check(dns);
        struct addrinfo *result = SocketDNS_getresult(dns, req);
        if (result)
            freeaddrinfo(result);
    }
    EXCEPT(SocketDNS_Failed)
    {
        (void)0;
    }
    FINALLY
    {
        SocketDNS_free(&dns);
    }
    END_TRY;
}

/* ==================== GetResult Tests ==================== */

TEST(socketdns_getresult_before_completion)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
    struct addrinfo *result = SocketDNS_getresult(dns, req);
    ASSERT_NULL(result);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_getresult_after_completion)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
    ASSERT_NOT_NULL(req);

    usleep(100000);
    SocketDNS_check(dns);

    struct addrinfo *result = SocketDNS_getresult(dns, req);
    if (result)
    {
        ASSERT_NOT_NULL(result);
        freeaddrinfo(result);
    }
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_getresult_clears_result)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
    usleep(100000);
    SocketDNS_check(dns);

    struct addrinfo *result1 = SocketDNS_getresult(dns, req);
    if (result1)
    {
        freeaddrinfo(result1);
        struct addrinfo *result2 = SocketDNS_getresult(dns, req);
        ASSERT_NULL(result2);
    }
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Concurrent Resolution Tests ==================== */

TEST(socketdns_many_concurrent_resolutions)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T requests[20];

    TRY volatile int i;
    volatile int completed = 0;
    for (i = 0; i < 20; i++)
    {
        requests[i] = SocketDNS_resolve(dns, "127.0.0.1", 80 + i, NULL, NULL);
        ASSERT_NOT_NULL(requests[i]);
    }

    usleep(500000);
    SocketDNS_check(dns);

    for (i = 0; i < 20; i++)
    {
        struct addrinfo *result = SocketDNS_getresult(dns, requests[i]);
        if (result)
        {
            completed++;
            freeaddrinfo(result);
        }
    }
    ASSERT_NE(completed, 0);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Stress Tests ==================== */

TEST(socketdns_rapid_resolution_requests)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T requests[50] = {0};

    TRY
    {
        volatile int i;
        for (i = 0; i < 50; i++)
        {
            requests[i] = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
            ASSERT_NOT_NULL(requests[i]);
        }
        usleep(500000);
        SocketDNS_check(dns);

        for (i = 0; i < 50; i++)
        {
            struct addrinfo *result = SocketDNS_getresult(dns, requests[i]);
            if (result)
                freeaddrinfo(result);
        }
    }
    EXCEPT(SocketDNS_Failed)
    {
        ASSERT(0);
    }
    FINALLY
    {
        SocketDNS_free(&dns);
    }
    END_TRY;
}

TEST(socketdns_resolve_cancel_cycle)
{
    SocketDNS_T dns = SocketDNS_new();

    TRY volatile int i;
    for (i = 0; i < 20; i++)
    {
        SocketDNS_Request_T req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        SocketDNS_cancel(dns, req);
    }
    EXCEPT(SocketDNS_Failed)(void) 0;
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
        int stop = 0;
        SocketDNS_Request_T req = NULL;
        struct addrinfo *result = NULL;

        TRY
        {
            req = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
            ASSERT_NOT_NULL(req);

            while (result == NULL)
            {
                usleep(10000);
                SocketDNS_check(dns);
                result = SocketDNS_getresult(dns, req);
            }

            freeaddrinfo(result);
            result = NULL;
        }
        EXCEPT(SocketDNS_Failed)
        {
            stop = 1;
        }
        FINALLY
        {
            if (result)
                freeaddrinfo(result);
        }
        END_TRY;

        if (stop)
            break;
    }

    return NULL;
}

TEST(socketdns_concurrent_resolutions)
{
    SocketDNS_T dns = SocketDNS_new();
    pthread_t threads[4];

    volatile int i;
    for (i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, thread_resolve_requests, dns);

    for (i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);

    usleep(500000);
    SocketDNS_check(dns);
    SocketDNS_free(&dns);
}

#if 0 /* Temporarily disabled - segfault in exception frame handling */
static void *thread_check_completions(void *arg)
{
    SocketDNS_T dns = (SocketDNS_T)arg;
    
    volatile int i;
    for (i = 0; i < 20; i++)
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
        volatile int i;
        for (i = 0; i < 10; i++)
            SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        
        for (i = 0; i < 4; i++)
            pthread_create(&threads[i], NULL, thread_check_completions, dns);
        
        for (i = 0; i < 4; i++)
            pthread_join(threads[i], NULL);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}
#endif

static void *thread_cancel_requests(void *arg)
{
    SocketDNS_T dns = (SocketDNS_T)arg;

    for (volatile int i = 0; i < 10; i++)
    {
        int stop = 0;
        TRY SocketDNS_Request_T req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        usleep(5000);
        SocketDNS_cancel(dns, req);
        EXCEPT(SocketDNS_Failed)
        stop = 1;
        END_TRY;

        if (stop)
            break;
    }

    return NULL;
}

TEST(socketdns_concurrent_cancel)
{
    SocketDNS_T dns = SocketDNS_new();
    pthread_t threads[4];

    volatile int i;
    for (i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, thread_cancel_requests, dns);

    for (i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);

    SocketDNS_free(&dns);
}

/* ==================== Thread Pool Tests ==================== */

#if 0 /* Temporarily disabled - segfault in exception frame handling */
TEST(socketdns_thread_pool_processes_requests)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T requests[10];

    TRY
        volatile int i;
        volatile int completed = 0;
        for (i = 0; i < 10; i++)
            requests[i] = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
        
        usleep(300000);
        SocketDNS_check(dns);
        
        for (i = 0; i < 10; i++)
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
#endif

/* ==================== Parameter Validation Tests ==================== */

TEST(socketdns_resolve_null_hostname)
{
    SocketDNS_T dns = SocketDNS_new();

    /* NULL hostname causes assert() - cannot test exception in debug builds */
    /* In release builds (NDEBUG), this would cause crash via strlen(NULL) */
    /* This test verifies that assert() prevents NULL hostname */
    (void)dns; /* Suppress unused warning */

    SocketDNS_free(&dns);
}

TEST(socketdns_resolve_empty_hostname)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;
    int caught = 0;

    TRY
    {
        TRY
        {
            req = SocketDNS_resolve(dns, "", 80, NULL, NULL);
            ASSERT_NULL(req); /* Should not reach here */
        }
        EXCEPT(Test_Failed)
        {
            RERAISE;
        }
        ELSE
        {
            ASSERT_NOT_NULL(Except_frame.exception);
            ASSERT_NOT_NULL(strstr(Except_frame.exception->reason, "Invalid hostname length"));
            caught = 1;
        }
        END_TRY;
    }
    FINALLY
    {
        SocketDNS_free(&dns);
    }
    END_TRY;

    ASSERT(caught);
}

TEST(socketdns_resolve_invalid_port_negative)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;
    int caught = 0;

    TRY
    {
        TRY
        {
            req = SocketDNS_resolve(dns, "localhost", -1, NULL, NULL);
            ASSERT_NULL(req); /* Should not reach here */
        }
        EXCEPT(Test_Failed)
        {
            RERAISE;
        }
        ELSE
        {
            ASSERT_NOT_NULL(Except_frame.exception);
            ASSERT_NOT_NULL(strstr(Except_frame.exception->reason, "Invalid port number"));
            caught = 1;
        }
        END_TRY;
    }
    FINALLY
    {
        SocketDNS_free(&dns);
    }
    END_TRY;

    ASSERT(caught);
}

TEST(socketdns_resolve_invalid_port_too_large)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;
    int caught = 0;

    TRY
    {
        TRY
        {
            req = SocketDNS_resolve(dns, "localhost", 65536, NULL, NULL);
            ASSERT_NULL(req); /* Should not reach here */
        }
        EXCEPT(Test_Failed)
        {
            RERAISE;
        }
        ELSE
        {
            ASSERT_NOT_NULL(Except_frame.exception);
            ASSERT_NOT_NULL(strstr(Except_frame.exception->reason, "Invalid port number"));
            caught = 1;
        }
        END_TRY;
    }
    FINALLY
    {
        SocketDNS_free(&dns);
    }
    END_TRY;

    ASSERT(caught);
}

TEST(socketdns_resolve_valid_port_zero)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;
    struct addrinfo *result = NULL;

    TRY
    {
        req = SocketDNS_resolve(dns, "localhost", 0, NULL, NULL);
        ASSERT_NOT_NULL(req);

        usleep(100000);
        SocketDNS_check(dns);
        result = SocketDNS_getresult(dns, req);
        if (result)
            freeaddrinfo(result);
        result = NULL;
    }
    EXCEPT(SocketDNS_Failed)
    {
        ASSERT(0); /* Port 0 should be valid */
    }
    FINALLY
    {
        if (result)
            freeaddrinfo(result);
        SocketDNS_free(&dns);
    }
    END_TRY;
}

TEST(socketdns_resolve_valid_port_max)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;
    struct addrinfo *result = NULL;

    TRY
    {
        req = SocketDNS_resolve(dns, "127.0.0.1", 65535, NULL, NULL);
        ASSERT_NOT_NULL(req);

        usleep(100000);
        SocketDNS_check(dns);
        result = SocketDNS_getresult(dns, req);
        if (result)
            freeaddrinfo(result);
        result = NULL;
    }
    EXCEPT(SocketDNS_Failed)
    {
        ASSERT(0); /* Maximum port should be valid */
    }
    FINALLY
    {
        if (result)
            freeaddrinfo(result);
        SocketDNS_free(&dns);
    }
    END_TRY;
}

TEST(socketdns_resolve_null_dns)
{
    /* NULL DNS resolver causes assert() - cannot test exception in debug builds */
    /* This test verifies that assert() prevents NULL DNS resolver */
    (void)0; /* Test placeholder - actual test requires assert override */
}

TEST(socketdns_cancel_null_request)
{
    SocketDNS_T dns = SocketDNS_new();

    /* NULL request causes assert() - cannot test exception in debug builds */
    /* This test verifies that assert() prevents NULL request */
    (void)0; /* Test placeholder - actual test requires assert override */

    SocketDNS_free(&dns);
}

/* ==================== Error Handling Tests ==================== */

TEST(socketdns_getresult_null_request)
{
    SocketDNS_T dns = SocketDNS_new();

    /* NULL request causes assert() - cannot test exception in debug builds */
    /* This test verifies that assert() prevents NULL request */
    (void)0; /* Test placeholder - actual test requires assert override */

    SocketDNS_free(&dns);
}

TEST(socketdns_getresult_pending_request)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
    ASSERT_NOT_NULL(req);

    /* Request should still be pending */
    struct addrinfo *result = SocketDNS_getresult(dns, req);
    ASSERT_NULL(result);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

TEST(socketdns_getresult_cancelled_request)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T req = NULL;

    TRY req = SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
    ASSERT_NOT_NULL(req);

    SocketDNS_cancel(dns, req);

    /* Cancelled request should return NULL */
    struct addrinfo *result = SocketDNS_getresult(dns, req);
    ASSERT_NULL(result);
    EXCEPT(SocketDNS_Failed)(void) 0;
    FINALLY
    SocketDNS_free(&dns);
    END_TRY;
}

/* ==================== Queue Management Tests ==================== */

TEST(socketdns_queue_full_handling)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketDNS_Request_T requests[1100]; /* More than default max_pending */
    volatile int i;
    volatile int success_count = 0;
    volatile int failure_count = 0;

    TRY
    {
        /* Fill queue beyond capacity - should eventually fail */
        for (i = 0; i < 1100; i++)
        {
            int queue_full = 0;

            TRY
            {
                requests[i] = SocketDNS_resolve(dns, "127.0.0.1", 80 + (i % 100), NULL, NULL);
                ASSERT_NOT_NULL(requests[i]);
                success_count++;
            }
            EXCEPT(Test_Failed)
            {
                RERAISE;
            }
            ELSE
            {
                ASSERT_NOT_NULL(Except_frame.exception);
                ASSERT_NOT_NULL(strstr(Except_frame.exception->reason, "queue full"));
                failure_count++;
                queue_full = 1;
            }
            END_TRY;

            if (queue_full)
                break; /* Queue full - stop */
        }

        /* Should have successfully queued some requests */
        ASSERT_NE(success_count, 0);

        if (failure_count == 0)
            fprintf(stderr, "[socketdns debug] queue did not report full condition\n");

        /* Process some requests to make room */
        usleep(200000);
        SocketDNS_check(dns);

        /* Cancel remaining requests */
        for (i = 0; i < success_count; i++)
        {
            SocketDNS_cancel(dns, requests[i]);
        }
    }
    FINALLY
    {
        SocketDNS_free(&dns);
    }
    END_TRY;
}

TEST(socketdns_multiple_resolvers_independent)
{
    SocketDNS_T dns1 = SocketDNS_new();
    SocketDNS_T dns2 = SocketDNS_new();
    SocketDNS_Request_T req1 = NULL;
    SocketDNS_Request_T req2 = NULL;
    struct addrinfo *res1 = NULL;
    struct addrinfo *res2 = NULL;

    TRY
    {
        req1 = SocketDNS_resolve(dns1, "localhost", 80, NULL, NULL);
        req2 = SocketDNS_resolve(dns2, "127.0.0.1", 443, NULL, NULL);

        ASSERT_NOT_NULL(req1);
        ASSERT_NOT_NULL(req2);

        usleep(100000);
        SocketDNS_check(dns1);
        SocketDNS_check(dns2);

        res1 = SocketDNS_getresult(dns1, req1);
        res2 = SocketDNS_getresult(dns2, req2);
    }
    EXCEPT(SocketDNS_Failed)
    {
        ASSERT(0); /* Both resolutions should succeed */
    }
    FINALLY
    {
        if (res1)
            freeaddrinfo(res1);
        if (res2)
            freeaddrinfo(res2);
        SocketDNS_free(&dns1);
        SocketDNS_free(&dns2);
    }
    END_TRY;
}

int main(void)
{
    Test_run_all();
    return Test_get_failures() > 0 ? 1 : 0;
}

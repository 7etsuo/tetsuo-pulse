#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"

#define BENCH_HOST "127.0.0.1"
#define BENCH_PORT 8080
#define BENCH_NUM_REQS 100000
#define BENCH_THREADS 10
#define BENCH_MSG_SIZE 64

static volatile int client_running = 1;
static pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;
static long total_reqs = 0;
static long successful_reqs = 0;
static long failed_reqs = 0;
static long total_latency_us = 0; // Microseconds

struct bench_thread_arg
{
    int thread_id;
    long reqs_per_thread;
    int port;
};

/* Single connection benchmark thread */
static void *bench_thread(void *arg)
{
    struct bench_thread_arg *targ = (struct bench_thread_arg *)arg;
    int thread_id = targ->thread_id;
    long reqs_per_thread = targ->reqs_per_thread;
    int port = targ->port;
    free(arg); /* Free the structure */

    Arena_T arena = Arena_new();

    TRY
    {
        for (volatile long i = 0; i < reqs_per_thread && client_running; i++)
        {
            struct timeval start, end;
            Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
            volatile int connected = 0;

            // Retry connection up to 5 times with exponential backoff
            volatile int retries = 0;
            while (retries < 5 && !connected)
            {
                TRY
                {
                    Socket_connect(sock, BENCH_HOST, port);
                    // Check if connection actually succeeded (Socket_connect may return gracefully on errors)
                    if (Socket_isconnected(sock))
                    {
                        connected = 1;
                    }
                    else
                    {
                        retries++;
                        if (retries < 5)
                        {
                            usleep(100000 * retries); // Exponential backoff: 100ms, 200ms, 400ms, 800ms
                        }
                    }
                }
                EXCEPT(Socket_Failed)
                {
                    retries++;
                    if (retries < 5)
                    {
                        usleep(100000 * retries); // Exponential backoff: 100ms, 200ms, 400ms, 800ms
                    }
                }
                END_TRY;
            }

            if (!connected)
            {
                pthread_mutex_lock(&client_mutex);
                failed_reqs++;
                total_reqs++;
                pthread_mutex_unlock(&client_mutex);
                Socket_free(&sock);
                continue;
            }

            gettimeofday(&start, NULL);
            char buf[BENCH_MSG_SIZE];
            memset(buf, 'A' + thread_id, sizeof(buf));
            volatile ssize_t sent = 0;
            volatile ssize_t recv_len = 0;

            TRY
            {
                sent = Socket_sendall(sock, buf, sizeof(buf));
                if (sent > 0)
                {
                    recv_len = Socket_recvall(sock, buf, sizeof(buf));
                }
            }
            EXCEPT(Socket_Closed)
            {
                // Connection closed by peer - count as failed
                sent = -1;
                recv_len = -1;
            }
            EXCEPT(Socket_Failed)
            {
                // Socket error after connect - count as failed
                sent = -1;
                recv_len = -1;
            }
            END_TRY;

            gettimeofday(&end, NULL);
            long latency_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
            pthread_mutex_lock(&client_mutex);
            if (sent > 0 && recv_len > 0)
            {
                successful_reqs++;
                total_latency_us += latency_us;
            }
            else
            {
                failed_reqs++;
            }
            total_reqs++;
            pthread_mutex_unlock(&client_mutex);

            Socket_free(&sock);
        }
    }
    EXCEPT(Arena_Failed)
    {
        pthread_mutex_lock(&client_mutex);
        failed_reqs += reqs_per_thread;
        total_reqs += reqs_per_thread;
        pthread_mutex_unlock(&client_mutex);
    }
    FINALLY
    {
        Arena_dispose(&arena);
    }
    END_TRY;

    return NULL;
}

int main(int argc, char **argv)
{
    int port = BENCH_PORT;
    long reqs = BENCH_NUM_REQS;
    int threads = BENCH_THREADS;

    // Parse args
    for (int i = 1; i < argc; i++)
    {
        if (strncmp(argv[i], "--port=", 7) == 0)
            port = atoi(argv[i] + 7);
        if (strncmp(argv[i], "--reqs=", 7) == 0)
            reqs = atol(argv[i] + 7);
        if (strncmp(argv[i], "--threads=", 10) == 0)
            threads = atoi(argv[i] + 10);
    }

    signal(SIGPIPE, SIG_IGN);

    // Wait for server to start
    sleep(1);

    printf("Benchmark client: %ld reqs across %d threads to %s:%d\n", reqs, threads, BENCH_HOST, port);

    pthread_t *pth = calloc(threads, sizeof(pthread_t));
    long reqs_per_thread = reqs / threads;

    for (int i = 0; i < threads; i++)
    {
        struct bench_thread_arg *targ = malloc(sizeof(struct bench_thread_arg));
        targ->thread_id = i;
        targ->reqs_per_thread = reqs_per_thread;
        targ->port = port;
        pthread_create(&pth[i], NULL, bench_thread, targ);
    }

    for (int i = 0; i < threads; i++)
    {
        pthread_join(pth[i], NULL);
    }

    double avg_latency_ms = total_latency_us > 0 ? total_latency_us / (double)successful_reqs / 1000.0 : 0;
    double throughput = (total_reqs > 0 && total_latency_us > 0) ? reqs / (total_latency_us / 1000000.0) : 0;

    printf("\nResults:\n");
    printf("Total reqs: %ld (success: %ld, fail: %ld)\n", total_reqs, successful_reqs, failed_reqs);
    printf("Avg latency: %.2f ms\n", avg_latency_ms);
    printf("Throughput: %.0f reqs/sec\n", throughput);

    free(pth);

    return 0;
}

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "pool/SocketPool.h"
#include "poll/SocketPoll.h"

#define STRESS_PORT 8080
#define STRESS_NUM_CLIENTS 10000
#define STRESS_MESSAGE_SIZE 1024
#define STRESS_NUM_MESSAGES 10
#define STRESS_NUM_THREADS 50

static volatile int running = 1;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static long total_connections = 0;
static long successful_connections = 0;
static long failed_connections = 0;

/* Thread function for client simulation */
static void *stress_client_thread(void *arg)
{
    int thread_id = *(int *)arg;
    free(arg);

    Arena_T arena = Arena_new();
    if (!arena)
    {
        fprintf(stderr, "Thread %d: Failed to allocate arena\n", thread_id);
        return NULL;
    }

    TRY
    {
        /* Simulate client connections */
        for (int i = 0; i < STRESS_NUM_CLIENTS / STRESS_NUM_THREADS && running; i++)
        {
            Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
            if (!client)
            {
                pthread_mutex_lock(&stats_mutex);
                failed_connections++;
                total_connections++;
                pthread_mutex_unlock(&stats_mutex);
                continue;
            }

            TRY
            {
                Socket_connect(client, "127.0.0.1", STRESS_PORT);
                pthread_mutex_lock(&stats_mutex);
                successful_connections++;
                total_connections++;
                pthread_mutex_unlock(&stats_mutex);

                /* Send some data */
                char buf[STRESS_MESSAGE_SIZE];
                memset(buf, 'A' + (thread_id % 26), sizeof(buf));
                ssize_t sent = Socket_sendall(client, buf, sizeof(buf));
                if (sent > 0)
                {
                    ssize_t received = Socket_recvall(client, buf, sizeof(buf));
                    (void)received; // Suppress unused if not needed
                }

                Socket_free(&client);
            }
            EXCEPT(Socket_Failed)
            {
                pthread_mutex_lock(&stats_mutex);
                failed_connections++;
                total_connections++;
                pthread_mutex_unlock(&stats_mutex);
                Socket_free(&client);
            }
            END_TRY;
        }
    }
    EXCEPT(Arena_Failed)
    {
        fprintf(stderr, "Thread %d: Arena allocation failed\n", thread_id);
    }
    FINALLY
    {
        Arena_dispose(&arena);
    }
    END_TRY;

    return NULL;
}

/* Simple echo server for stress testing */
static void *stress_echo_server(void *arg)
{
    (void)arg;

    Arena_T arena = Arena_new();
    if (!arena)
    {
        fprintf(stderr, "Server: Failed to allocate arena\n");
        return NULL;
    }

    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    if (!server)
    {
        Arena_dispose(&arena);
        fprintf(stderr, "Server: Failed to create socket\n");
        return NULL;
    }

    TRY
    {
        Socket_bind(server, "127.0.0.1", STRESS_PORT);
        Socket_listen(server, SOMAXCONN);
        Socket_setnonblocking(server);

        SocketPoll_T poll = SocketPoll_new(1024);
        if (!poll)
        {
            Socket_free(&server);
            Arena_dispose(&arena);
            return NULL;
        }

        SocketPoll_add(poll, server, POLL_READ, NULL);

        while (running)
        {
            SocketEvent_T *events;
            int n = SocketPoll_wait(poll, &events, 1000);

            for (int i = 0; i < n; i++)
            {
                if (events[i].socket == server)
                {
                    TRY
                    {
                        Socket_T client = Socket_accept(server);
                        if (client)
                        {
                            SocketPoll_add(poll, client, POLL_READ | POLL_WRITE, client);
                        }
                    }
                    EXCEPT(Socket_Failed)
                    {
                        // Accept failed - continue
                    }
                    END_TRY;
                }
                else
                {
                    char buf[STRESS_MESSAGE_SIZE];
                    ssize_t recv_len = Socket_recv(events[i].socket, buf, sizeof(buf));
                    if (recv_len > 0)
                    {
                        Socket_sendall(events[i].socket, buf, recv_len);
                    }
                    else
                    {
                        SocketPoll_del(poll, events[i].socket);
                        Socket_free(&events[i].socket);
                    }
                }
            }
        }

        SocketPoll_free(&poll);
        Socket_free(&server);
    }
    EXCEPT(Socket_Failed)
    {
        fprintf(stderr, "Server: Socket operation failed\n");
    }
    EXCEPT(Arena_Failed)
    {
        fprintf(stderr, "Server: Arena failed\n");
    }
    FINALLY
    {
        Arena_dispose(&arena);
    }
    END_TRY;

    return NULL;
}

int main()
{
    signal(SIGPIPE, SIG_IGN);

    printf("Starting socket library stress test: %d clients across %d threads\n", STRESS_NUM_CLIENTS,
           STRESS_NUM_THREADS);

    /* Start echo server */
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, stress_echo_server, NULL);

    /* Start client threads */
    pthread_t *threads = calloc(STRESS_NUM_THREADS, sizeof(pthread_t));
    int *thread_ids = malloc(STRESS_NUM_THREADS * sizeof(int));

    for (int i = 0; i < STRESS_NUM_THREADS; i++)
    {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, stress_client_thread, &thread_ids[i]);
    }

    /* Wait for completion */
    sleep(STRESS_NUM_MESSAGES * 2); // Allow time for stress
    running = 0;

    for (int i = 0; i < STRESS_NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }
    pthread_join(server_thread, NULL);

    /* Report results */
    pthread_mutex_lock(&stats_mutex);
    printf("\nStress Test Results:\n");
    printf("Total connection attempts: %ld\n", total_connections);
    printf("Successful connections: %ld (%.1f%%)\n", successful_connections,
           total_connections > 0 ? (double)successful_connections / total_connections * 100 : 0);
    printf("Failed connections: %ld (%.1f%%)\n", failed_connections,
           total_connections > 0 ? (double)failed_connections / total_connections * 100 : 0);
    pthread_mutex_unlock(&stats_mutex);

    /* Check for leaks */
    if (Socket_debug_live_count() != 0)
    {
        fprintf(stderr, "ERROR: %d socket leaks detected!\n", Socket_debug_live_count());
        return 1;
    }

    printf("No socket leaks detected.\n");
    free(threads);
    free(thread_ids);

    return 0;
}

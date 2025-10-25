#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "Arena.h"
#include "Except.h"
#include "Socket.h"
#include "SocketBuf.h"
#include "SocketPoll.h"
#include "SocketPool.h"
#include "SocketConfig.h"

/* Use sig_atomic_t for signal safety */
static volatile sig_atomic_t running = 1;
static SocketPoll_T global_poll = NULL; /* For cleanup access */

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* Helper function to remove a connection from poll during shutdown */
static void remove_from_poll(Connection_T conn, void *arg)
{
    SocketPoll_T poll = (SocketPoll_T)arg;
    if (conn && Connection_isactive(conn))
    {
        SocketPoll_del(poll, Connection_socket(conn));
    }
}

/* Returns 1 if connection is still active, 0 if closed */
static int handle_client_data(Connection_T conn, SocketPoll_T poll)
{
    char buffer[4096];
    ssize_t bytes_received;
    volatile int active = 1;

    Socket_T sock = Connection_socket(conn);

    TRY bytes_received = Socket_recv(sock, buffer, sizeof(buffer) - 1);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0';
        printf("Client %s:%d: %s", Socket_getpeeraddr(sock), Socket_getpeerport(sock), buffer);
        fflush(stdout);

        /* Echo back to client */
        if (SocketBuf_write(Connection_outbuf(conn), buffer, bytes_received) < (size_t)bytes_received)
        {
            printf("Output buffer full for client %s:%d\n", Socket_getpeeraddr(Connection_socket(conn)),
                   Socket_getpeerport(Connection_socket(conn)));
            fflush(stdout);
        }
        else
        {
            /* Enable write events */
            SocketPoll_mod(poll, sock, POLL_READ | POLL_WRITE, conn);
        }
    }
    EXCEPT(Socket_Closed)
    printf("Client disconnected\n");
    active = 0;
    END_TRY;

    return active;
}

/* Returns 1 if connection is still active, 0 if closed */
static int handle_client_write(Connection_T conn, SocketPoll_T poll)
{
    size_t len;
    const void *data;
    ssize_t sent;
    volatile int active = 1;

    data = SocketBuf_readptr(Connection_outbuf(conn), &len);
    if (data && len > 0)
    {
        TRY sent = Socket_send(Connection_socket(conn), data, len);
        if (sent > 0)
        {
            SocketBuf_consume(Connection_outbuf(conn), sent);
        }
        EXCEPT(Socket_Closed)
        printf("Client disconnected during write\n");
        active = 0;
        END_TRY;
    }

    /* If output buffer is empty, disable write events */
    if (active && SocketBuf_empty(Connection_outbuf(conn)))
    {
        SocketPoll_mod(poll, Connection_socket(conn), POLL_READ, conn);
    }

    return active;
}

int main(int argc, char **argv)
{
    Socket_T server = NULL;
    SocketPoll_T poll = NULL;
    SocketPool_T pool = NULL;
    Arena_T arena = NULL;
    volatile int port = 6667;

    /* Set up signal handling */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    if (argc > 1)
    {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535)
        {
            fprintf(stderr, "Invalid port number: %s\n", argv[1]);
            return 1;
        }
    }

    TRY
        /* Create main arena for all allocations */
        arena = Arena_new();
    if (!arena)
    {
        fprintf(stderr, "Failed to create arena\n");
        RAISE(Socket_Failed);
    }

    /* Create server socket - AF_INET6 with dual-stack support */
    server = Socket_new(AF_INET6, SOCK_STREAM, 0);
    Socket_setreuseaddr(server);
    Socket_bind(server, NULL, port); /* Bind to all addresses (dual-stack) */
    Socket_listen(server, SOCKET_MAX_LISTEN_BACKLOG);
    Socket_setnonblocking(server);

    printf("IRC server listening on port %d\n", port);

    /* Create event poll */
    poll = SocketPoll_new(SOCKET_DEFAULT_POOL_SIZE);
    global_poll = poll; /* Save for signal handler access */
    SocketPoll_add(poll, server, POLL_READ, NULL);

    /* Create connection pool */
    pool = SocketPool_new(arena, SOCKET_DEFAULT_POOL_SIZE, SOCKET_DEFAULT_POOL_BUFSIZE);

    /* Main event loop */
    while (running)
    {
        SocketEvent_T *events;
        volatile int event_count, i;

        event_count = SocketPoll_wait(poll, &events, SOCKET_DEFAULT_POLL_TIMEOUT);

        /* Check if we're shutting down before processing events */
        if (!running)
            break;

        for (i = 0; i < event_count; i++)
        {
            if (events[i].socket == server)
            {
                /* Accept new connection */
                Socket_T client = NULL;
                TRY client = Socket_accept(server);
                if (client)
                {
                    Connection_T conn = SocketPool_add(pool, client);
                    if (conn)
                    {
                        printf("New connection from %s:%d\n", Socket_getpeeraddr(client), Socket_getpeerport(client));
                        SocketPoll_add(poll, client, POLL_READ, conn);
                    }
                    else
                    {
                        printf("Connection pool full, rejecting client\n");
                        Socket_free(&client);
                    }
                }
                EXCEPT(Socket_Failed)
                printf("Failed to accept connection\n");
                END_TRY;
            }
            else
            {
                /* Handle client socket */
                Connection_T conn = SocketPool_get(pool, events[i].socket);
                if (conn)
                {
                    volatile int active = 1;

                    TRY if (events[i].events & POLL_READ)
                    {
                        active = handle_client_data(conn, poll);
                    }

                    if (active && (events[i].events & POLL_WRITE))
                    {
                        active = handle_client_write(conn, poll);
                    }

                    if (active && (events[i].events & (POLL_ERROR | POLL_HANGUP)))
                    {
                        printf("Error on client socket\n");
                        active = 0;
                    }
                    EXCEPT(Socket_Closed)
                    active = 0;
                    EXCEPT(Socket_Failed)
                    printf("Socket error: %s\n", Socket_Failed.reason);
                    active = 0;
                    END_TRY;

                    /* Clean up disconnected client */
                    if (!active)
                    {
                        Socket_T sock = Connection_socket(conn);
                        SocketPoll_del(poll, sock);
                        SocketPool_remove(pool, sock);
                        Socket_free(&sock);
                    }
                }
            }
        }

        /* Clean up idle connections */
        SocketPool_cleanup(pool, SOCKET_DEFAULT_IDLE_TIMEOUT);
    }

    printf("\nShutting down server...\n");

    EXCEPT(Socket_Failed)
    fprintf(stderr, "Socket error: %s\n", Socket_Failed.reason);
    EXCEPT(SocketPoll_Failed)
    fprintf(stderr, "Poll error: %s\n", SocketPoll_Failed.reason);
    EXCEPT(Socket_Closed)
    /* Socket closed during shutdown is expected */
    FINALLY
    /* Clean up all connections first */
    if (pool && poll)
    {
        /* First remove all sockets from poll to prevent events during shutdown */
        SocketPool_foreach(pool, remove_from_poll, poll);

        /* Now safe to cleanup - this will close all client sockets immediately */
        SocketPool_cleanup(pool, 0);
    }

    /* Remove server socket from poll first */
    if (server && poll)
        SocketPoll_del(poll, server);

    if (poll)
    {
        global_poll = NULL; /* Clear global reference */
        SocketPoll_free(&poll);
    }

    if (pool)
        SocketPool_free(&pool);

    if (server)
        Socket_free(&server);

    if (arena)
        Arena_dispose(&arena);
    END_TRY;

    return 0;
}

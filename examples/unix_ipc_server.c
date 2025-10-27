/**
 * Unix Domain Socket IPC Server Example
 *
 * Demonstrates using Unix domain sockets for inter-process communication.
 * Creates a Unix socket server that echoes messages back to clients.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../Arena.h"
#include "../Except.h"
#include "../Socket.h"

#define SOCKET_PATH "/tmp/ipc_server.sock"

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

int main(void)
{
    Arena_T arena = NULL;
    Socket_T server = NULL;
    Socket_T client = NULL;

    /* Set up signal handling */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    TRY
        /* Create arena */
        arena = Arena_new();
    if (!arena)
    {
        fprintf(stderr, "Failed to create arena\n");
        RAISE(Socket_Failed);
    }

    /* Remove old socket file if it exists */
    unlink(SOCKET_PATH);

    /* Create Unix domain socket */
    server = Socket_new(AF_UNIX, SOCK_STREAM, 0);
    Socket_bind_unix(server, SOCKET_PATH);
    Socket_listen(server, 5);
    Socket_setnonblocking(server);

    printf("Unix domain socket server listening at %s\n", SOCKET_PATH);
    printf("Press Ctrl+C to stop\n");

    /* Main loop */
    while (running)
    {
        /* Try to accept new connection */
        client = Socket_accept(server);

        if (client)
        {
            pid_t pid = Socket_getpeerpid(client);
            uid_t uid = Socket_getpeeruid(client);
            gid_t gid = Socket_getpeergid(client);

            printf("New connection from PID=%d, UID=%d, GID=%d\n", pid, uid, gid);

            /* Handle client */
            char buffer[4096];
            ssize_t received;

            TRY while ((received = Socket_recv(client, buffer, sizeof(buffer) - 1)) > 0)
            {
                buffer[received] = '\0';
                printf("Received: %s", buffer);

                /* Echo back */
                Socket_send(client, buffer, received);
            }
            EXCEPT(Socket_Closed)
            printf("Client disconnected\n");
            END_TRY;

            Socket_free(&client);
        }
        else
        {
            /* No connection available - sleep briefly */
            usleep(100000); /* 100ms */
        }
    }

    printf("\nShutting down server...\n");

    EXCEPT(Socket_Failed)
    fprintf(stderr, "Socket error: %s\n", Socket_Failed.reason);
    FINALLY
    if (client)
        Socket_free(&client);
    if (server)
    {
        Socket_free(&server);
        unlink(SOCKET_PATH); /* Clean up socket file */
    }
    if (arena)
        Arena_dispose(&arena);
    END_TRY;

    return 0;
}

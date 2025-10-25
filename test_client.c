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

/* Helper function to handle the connection */
static void handle_connection(const char *host, int port)
{
    Arena_T arena = NULL;
    Socket_T client = NULL;

    TRY
        /* Create arena */
        arena = Arena_new();
    if (!arena)
    {
        fprintf(stderr, "Failed to create arena\n");
        RAISE(Socket_Failed);
    }

    /* Create client socket */
    client = Socket_new(AF_INET, SOCK_STREAM, 0);

    /* Set timeout to prevent hanging */
    Socket_settimeout(client, 10);

    /* Enable keepalive */
    Socket_setkeepalive(client, 60, 10, 6);

    /* Connect (now supports DNS resolution) */
    Socket_connect(client, host, port);

    printf("Connected to %s:%d\n", host, port);

    /* Send test message */
    const char *msg = "Hello from test client!\r\n";
    ssize_t sent = Socket_send(client, msg, strlen(msg));
    printf("Sent %zd bytes\n", sent);

    /* Receive response */
    char buffer[1024];
    ssize_t received = Socket_recv(client, buffer, sizeof(buffer) - 1);
    if (received > 0)
    {
        buffer[received] = '\0';
        printf("Received %zd bytes: %s", received, buffer);
    }

    EXCEPT(Socket_Failed)
    fprintf(stderr, "Socket error: %s\n", Socket_Failed.reason);
    EXCEPT(Socket_Closed)
    fprintf(stderr, "Connection closed by server\n");
    FINALLY
    if (client)
        Socket_free(&client);
    if (arena)
        Arena_dispose(&arena);
    END_TRY;
}

int main(int argc, char **argv)
{
    const char *host = "localhost";
    int port = 6667;

    if (argc > 1)
        host = argv[1];
    if (argc > 2)
        port = atoi(argv[2]);

    printf("Connecting to %s:%d...\n", host, port);

    handle_connection(host, port);

    return 0;
}

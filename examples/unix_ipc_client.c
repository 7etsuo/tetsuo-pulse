/**
 * Unix Domain Socket IPC Client Example
 *
 * Demonstrates connecting to a Unix domain socket server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../Arena.h"
#include "../Except.h"
#include "../Socket.h"

#define SOCKET_PATH "/tmp/ipc_server.sock"

int main(void)
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

    /* Create and connect Unix domain socket */
    client = Socket_new(AF_UNIX, SOCK_STREAM, 0);
    Socket_connect_unix(client, SOCKET_PATH);

    printf("Connected to Unix domain socket server\n");

    /* Send test message */
    const char *msg = "Hello from IPC client!\n";
    Socket_send(client, msg, strlen(msg));
    printf("Sent: %s", msg);

    /* Receive echo */
    char buffer[1024];
    ssize_t received = Socket_recv(client, buffer, sizeof(buffer) - 1);
    if (received > 0)
    {
        buffer[received] = '\0';
        printf("Received echo: %s", buffer);
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

    return 0;
}

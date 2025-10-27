/**
 * UDP Echo Server Example
 *
 * Demonstrates using SocketDgram for UDP communication.
 * Receives datagrams and echoes them back to the sender.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../Arena.h"
#include "../Except.h"
#include "../SocketDgram.h"

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char **argv)
{
    Arena_T arena = NULL;
    SocketDgram_T server = NULL;
    volatile int port = 5000;
    char buffer[65536]; /* Max UDP payload */
    char sender_host[256];
    int sender_port;

    /* Parse arguments */
    if (argc > 1)
    {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535)
        {
            fprintf(stderr, "Invalid port number: %s\n", argv[1]);
            return 1;
        }
    }

    /* Set up signal handling */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    TRY
        /* Create arena */
        arena = Arena_new();
    if (!arena)
    {
        fprintf(stderr, "Failed to create arena\n");
        RAISE(SocketDgram_Failed);
    }

    /* Create UDP socket */
    server = SocketDgram_new(AF_INET, 0);
    SocketDgram_setreuseaddr(server);
    SocketDgram_bind(server, NULL, port); /* Bind to all addresses */

    /* Set timeout so recvfrom doesn't block forever
     * This makes the server responsive to Ctrl+C (SIGINT) */
    SocketDgram_settimeout(server, 1); /* 1 second timeout */

    printf("UDP echo server listening on port %d\n", port);
    printf("Press Ctrl+C to stop\n");

    /* Main loop */
    while (running)
    {
        ssize_t received =
            SocketDgram_recvfrom(server, buffer, sizeof(buffer) - 1, sender_host, sizeof(sender_host), &sender_port);

        if (received > 0)
        {
            buffer[received] = '\0';
            printf("Received %zd bytes from %s:%d: %s", received, sender_host, sender_port, buffer);

            /* Echo back */
            ssize_t sent = SocketDgram_sendto(server, buffer, received, sender_host, sender_port);
            if (sent > 0)
            {
                printf("Echoed %zd bytes back\n", sent);
            }
        }
        /* received == 0 means timeout - loop continues and checks running flag */
    }

    printf("\nShutting down server...\n");

    EXCEPT(SocketDgram_Failed)
    fprintf(stderr, "UDP error: %s\n", SocketDgram_Failed.reason);
    FINALLY
    if (server)
        SocketDgram_free(&server);
    if (arena)
        Arena_dispose(&arena);
    END_TRY;

    return 0;
}

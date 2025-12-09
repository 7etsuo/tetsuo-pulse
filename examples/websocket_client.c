/**
 * websocket_client.c - WebSocket Client Example
 *
 * Demonstrates connecting to a WebSocket server, sending and receiving
 * messages.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_websocket_client
 *
 * Usage:
 *   ./example_websocket_client [host] [port] [path]
 *   ./example_websocket_client echo.websocket.org 80 /
 *   ./example_websocket_client localhost 8080 /ws
 *
 * Note: For wss:// (TLS), you would use SocketTLS to wrap the socket
 * before creating the WebSocket.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketWS.h"

/* Global flag for shutdown */
static volatile int running = 1;

static void
signal_handler (int signo)
{
  (void)signo;
  running = 0;
}

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile host = "echo.websocket.events";
  volatile int port = 80;
  const char *volatile path = "/";
  Socket_T sock = NULL;
  SocketWS_T ws = NULL;
  SocketWS_Config config;
  volatile int result = 0;

  /* Parse command line arguments */
  if (argc > 1)
    host = argv[1];
  if (argc > 2)
    port = atoi (argv[2]);
  if (argc > 3)
    path = argv[3];

  /* Setup signal handlers */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  printf ("WebSocket Client Example\n");
  printf ("========================\n\n");
  printf ("Connecting to ws://%s:%d%s\n\n", host, port, path);

  TRY
  {
    /* Create TCP socket */
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Connect to server */
    Socket_connect (sock, host, port);
    printf ("TCP connection established\n");

    /* Configure WebSocket */
    SocketWS_config_defaults (&config);
    config.role = WS_ROLE_CLIENT;
    config.validate_utf8 = 1;
    config.ping_interval_ms = 30000; /* Auto-ping every 30 seconds */

    /* Create WebSocket client */
    ws = SocketWS_client_new (sock, host, path, &config);

    /* Perform WebSocket handshake */
    printf ("Performing WebSocket handshake...\n");
    while (SocketWS_handshake (ws) > 0)
      {
        /* Handshake in progress, would block */
        /* For non-blocking sockets, you'd poll here */
      }

    if (SocketWS_state (ws) != WS_STATE_OPEN)
      {
        fprintf (stderr, "Handshake failed: %s\n",
                 SocketWS_error_string (SocketWS_last_error (ws)));
        result = 1;
      }
    else
      {
        printf ("WebSocket connection established!\n");

        /* Check negotiated subprotocol */
        const char *subproto = SocketWS_selected_subprotocol (ws);
        if (subproto)
          {
            printf ("Subprotocol: %s\n", subproto);
          }

        /* Check if compression was negotiated */
        if (SocketWS_compression_enabled (ws))
          {
            printf ("Compression: enabled (permessage-deflate)\n");
          }

        printf ("\n");

        /* Send a text message */
        const char *message = "Hello from Socket Library WebSocket client!";
        printf ("Sending: %s\n", message);
        if (SocketWS_send_text (ws, message, strlen (message)) < 0)
          {
            fprintf (stderr, "Failed to send message\n");
            result = 1;
          }
        else
          {
            /* Wait for echo response */
            printf ("Waiting for response...\n");

            SocketWS_Message msg;
            int recv_result = SocketWS_recv_message (ws, &msg);

            if (recv_result > 0)
              {
                printf ("Received (%s, %zu bytes): ",
                        msg.type == WS_OPCODE_TEXT ? "text" : "binary",
                        msg.len);
                if (msg.type == WS_OPCODE_TEXT)
                  {
                    printf ("%.*s\n", (int)msg.len, (char *)msg.data);
                  }
                else
                  {
                    printf ("[binary data]\n");
                  }
                free (msg.data);
              }
            else if (recv_result == 0)
              {
                printf ("Server closed connection\n");
                printf ("Close code: %d\n", SocketWS_close_code (ws));
                const char *reason = SocketWS_close_reason (ws);
                if (reason)
                  {
                    printf ("Close reason: %s\n", reason);
                  }
              }
            else
              {
                fprintf (stderr, "Receive error: %s\n",
                         SocketWS_error_string (SocketWS_last_error (ws)));
              }

            /* Send another message */
            printf ("\nSending ping...\n");
            SocketWS_ping (ws, "ping", 4);

            /* Try to receive pong (may be automatic) */
            printf ("Sending binary data...\n");
            unsigned char binary_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
            SocketWS_send_binary (ws, binary_data, sizeof (binary_data));

            /* Receive the echo */
            recv_result = SocketWS_recv_message (ws, &msg);
            if (recv_result > 0)
              {
                printf ("Received binary echo: %zu bytes\n", msg.len);
                free (msg.data);
              }
          }

        /* Perform clean close */
        printf ("\nClosing connection...\n");
        SocketWS_close (ws, WS_CLOSE_NORMAL, "Example complete");

        /* Wait for close confirmation */
        SocketWS_Message close_msg;
        while (SocketWS_state (ws) != WS_STATE_CLOSED && running)
          {
            if (SocketWS_recv_message (ws, &close_msg) <= 0)
              {
                break;
              }
            free (close_msg.data);
          }

        printf ("Connection closed cleanly\n");
      }
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "Socket error\n");
    result = 1;
  }
  EXCEPT (SocketWS_Failed)
  {
    fprintf (stderr, "WebSocket error\n");
    result = 1;
  }
  EXCEPT (SocketWS_ProtocolError)
  {
    fprintf (stderr, "WebSocket protocol error\n");
    result = 1;
  }
  EXCEPT (SocketWS_Closed)
  {
    fprintf (stderr, "Connection closed unexpectedly\n");
    result = 1;
  }
  FINALLY
  {
    if (ws)
      {
        SocketWS_free (&ws);
      }
    if (sock)
      {
        Socket_free (&sock);
      }
  }
  END_TRY;

  return result;
}

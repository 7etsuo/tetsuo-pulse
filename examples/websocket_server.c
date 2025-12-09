/**
 * websocket_server.c - WebSocket Echo Server Example
 *
 * Demonstrates a WebSocket server that echoes messages back to clients.
 * Integrates with HTTP server for WebSocket upgrade handling.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_websocket_server
 *
 * Usage:
 *   ./example_websocket_server [port]
 *   ./example_websocket_server 8080
 *
 * Test with browser console:
 *   ws = new WebSocket('ws://localhost:8080/ws');
 *   ws.onmessage = (e) => console.log('Received:', e.data);
 *   ws.send('Hello, Server!');
 *
 * Or with the websocket_client example:
 *   ./example_websocket_client localhost 8080 /ws
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTPServer.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketWS.h"

/* Maximum WebSocket clients */
#define MAX_CLIENTS 100

/* Global state */
static volatile int running = 1;
static SocketWS_T ws_clients[MAX_CLIENTS];
static int ws_count = 0;

static void
signal_handler (int signo)
{
  (void)signo;
  running = 0;
}

/**
 * Add a WebSocket client to the list
 */
static int
add_ws_client (SocketWS_T ws)
{
  if (ws_count >= MAX_CLIENTS)
    {
      return -1;
    }
  ws_clients[ws_count++] = ws;
  return 0;
}

/**
 * Remove a WebSocket client from the list
 */
static void
remove_ws_client (SocketWS_T ws)
{
  for (int i = 0; i < ws_count; i++)
    {
      if (ws_clients[i] == ws)
        {
          /* Shift remaining clients */
          for (int j = i; j < ws_count - 1; j++)
            {
              ws_clients[j] = ws_clients[j + 1];
            }
          ws_count--;
          return;
        }
    }
}

/**
 * HTTP request handler
 *
 * Handles WebSocket upgrades and regular HTTP requests.
 */
static void
request_handler (SocketHTTPServer_Request_T req, void *userdata)
{
  (void)userdata;

  const char *path = SocketHTTPServer_Request_path (req);
  const char *client = SocketHTTPServer_Request_client_addr (req);

  printf ("[%s] Request: %s\n", client, path);

  /* Check for WebSocket upgrade */
  if (SocketHTTPServer_Request_is_websocket (req))
    {
      printf ("[%s] WebSocket upgrade requested\n", client);

      /* Accept the upgrade */
      SocketWS_T ws = SocketHTTPServer_Request_upgrade_websocket (req);

      if (ws)
        {
          printf ("[%s] WebSocket connection established\n", client);

          /* Complete handshake */
          while (SocketWS_handshake (ws) > 0)
            {
              /* Handshake in progress */
            }

          if (SocketWS_state (ws) == WS_STATE_OPEN)
            {
              if (add_ws_client (ws) == 0)
                {
                  printf ("[%s] WebSocket client added (total: %d)\n", client,
                          ws_count);
                }
              else
                {
                  printf ("[%s] Too many WebSocket clients\n", client);
                  SocketWS_close (ws, WS_CLOSE_TRY_AGAIN_LATER,
                                  "Too many clients");
                  SocketWS_free (&ws);
                }
            }
          else
            {
              printf ("[%s] WebSocket handshake failed\n", client);
              SocketWS_free (&ws);
            }
        }
      else
        {
          printf ("[%s] WebSocket upgrade failed\n", client);
        }

      /* Don't call finish - upgrade_websocket handles the response */
      return;
    }

  /* Regular HTTP handling */
  if (strcmp (path, "/") == 0)
    {
      /* Home page with WebSocket test interface */
      const char *html
          = "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "  <title>WebSocket Echo Server</title>\n"
            "  <style>\n"
            "    body { font-family: sans-serif; margin: 40px; }\n"
            "    #log { border: 1px solid #ccc; padding: 10px; height: 200px; "
            "overflow-y: scroll; background: #f9f9f9; }\n"
            "    input[type=text] { width: 300px; padding: 5px; }\n"
            "    button { padding: 5px 15px; }\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            "  <h1>WebSocket Echo Server</h1>\n"
            "  <p>Connect to test the WebSocket echo functionality.</p>\n"
            "  <p><button onclick=\"connect()\">Connect</button>\n"
            "     <button onclick=\"disconnect()\">Disconnect</button></p>\n"
            "  <p><input type=\"text\" id=\"msg\" placeholder=\"Enter "
            "message\">\n"
            "     <button onclick=\"sendMsg()\">Send</button></p>\n"
            "  <h3>Log:</h3>\n"
            "  <div id=\"log\"></div>\n"
            "  <script>\n"
            "    let ws = null;\n"
            "    function log(msg) {\n"
            "      const div = document.getElementById('log');\n"
            "      div.innerHTML += msg + '<br>';\n"
            "      div.scrollTop = div.scrollHeight;\n"
            "    }\n"
            "    function connect() {\n"
            "      if (ws) { log('Already connected'); return; }\n"
            "      const url = 'ws://' + location.host + '/ws';\n"
            "      log('Connecting to ' + url + '...');\n"
            "      ws = new WebSocket(url);\n"
            "      ws.onopen = () => log('Connected!');\n"
            "      ws.onmessage = (e) => log('Received: ' + e.data);\n"
            "      ws.onclose = (e) => { log('Disconnected: ' + e.code); ws = "
            "null; };\n"
            "      ws.onerror = () => log('Error');\n"
            "    }\n"
            "    function disconnect() {\n"
            "      if (ws) { ws.close(); ws = null; }\n"
            "    }\n"
            "    function sendMsg() {\n"
            "      const input = document.getElementById('msg');\n"
            "      if (ws && input.value) {\n"
            "        log('Sending: ' + input.value);\n"
            "        ws.send(input.value);\n"
            "        input.value = '';\n"
            "      }\n"
            "    }\n"
            "    document.getElementById('msg').addEventListener('keypress', "
            "(e) => {\n"
            "      if (e.key === 'Enter') sendMsg();\n"
            "    });\n"
            "  </script>\n"
            "</body>\n"
            "</html>\n";

      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type",
                                       "text/html; charset=utf-8");
      SocketHTTPServer_Request_body_string (req, html);
    }
  else
    {
      /* 404 for other paths */
      SocketHTTPServer_Request_status (req, 404);
      SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
      SocketHTTPServer_Request_body_string (req, "Not Found\n");
    }

  SocketHTTPServer_Request_finish (req);
}

/**
 * Process WebSocket clients
 */
static void
process_websocket_clients (void)
{
  for (int i = 0; i < ws_count; i++)
    {
      SocketWS_T ws = ws_clients[i];

      /* Check if connection is still open */
      if (SocketWS_state (ws) == WS_STATE_CLOSED)
        {
          printf ("WebSocket client disconnected\n");
          remove_ws_client (ws); /* Remove from array first */
          SocketWS_free (&ws);   /* Then free the WebSocket */
          i--;                   /* Adjust index after removal */
          continue;
        }

      /* Try to receive a message (non-blocking would require poll integration)
       */
      if (SocketWS_recv_available (ws))
        {
          SocketWS_Message msg;
          int recv_result = SocketWS_recv_message (ws, &msg);

          if (recv_result > 0)
            {
              printf ("Received %s message (%zu bytes)\n",
                      msg.type == WS_OPCODE_TEXT ? "text" : "binary", msg.len);

              /* Echo the message back */
              if (msg.type == WS_OPCODE_TEXT)
                {
                  SocketWS_send_text (ws, (const char *)msg.data, msg.len);
                }
              else
                {
                  SocketWS_send_binary (ws, msg.data, msg.len);
                }

              free (msg.data);
            }
          else if (recv_result == 0)
            {
              /* Connection closed */
              printf ("WebSocket client closed connection (code: %d)\n",
                      SocketWS_close_code (ws));
              remove_ws_client (ws); /* Remove from array first */
              SocketWS_free (&ws);   /* Then free the WebSocket */
              i--;
            }
        }
    }
}

int
main (int argc, char **argv)
{
  volatile int port = 8080;
  SocketHTTPServer_T server = NULL;
  SocketHTTPServer_Config config;
  volatile int result = 0;

  /* Parse port */
  if (argc > 1)
    {
      port = atoi (argv[1]);
      if (port <= 0 || port > 65535)
        {
          fprintf (stderr, "Invalid port: %s\n", argv[1]);
          return 1;
        }
    }

  /* Setup signals */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  /* Initialize client array */
  memset (ws_clients, 0, sizeof (ws_clients));

  printf ("WebSocket Echo Server Example\n");
  printf ("==============================\n\n");

  TRY
  {
    /* Configure HTTP server */
    SocketHTTPServer_config_defaults (&config);
    config.port = port;
    config.bind_address = "0.0.0.0";
    config.backlog = 128;
    config.max_connections = 100;
    config.keepalive_timeout_ms = 60000;

    /* Create server */
    server = SocketHTTPServer_new (&config);
    SocketHTTPServer_set_handler (server, request_handler, NULL);

    /* Start server */
    if (SocketHTTPServer_start (server) < 0)
      {
        fprintf (stderr, "Failed to start server\n");
        result = 1;
      }
    else
      {
        printf ("Server listening on http://0.0.0.0:%d\n", port);
        printf ("Open in browser: http://localhost:%d/\n", port);
        printf ("Press Ctrl+C to stop\n\n");

        /* Main event loop */
        while (running)
          {
            /* Process HTTP events */
            SocketHTTPServer_process (server, 100);

            /* Process WebSocket clients */
            process_websocket_clients ();
          }

        printf ("\nShutting down...\n");

        /* Close all WebSocket connections */
        for (int i = 0; i < ws_count; i++)
          {
            SocketWS_close (ws_clients[i], WS_CLOSE_GOING_AWAY,
                            "Server shutdown");
            SocketWS_free (&ws_clients[i]);
          }
        ws_count = 0;

        SocketHTTPServer_stop (server);
      }
  }
  EXCEPT (SocketHTTPServer_BindFailed)
  {
    fprintf (stderr, "Failed to bind to port %d\n", port);
    result = 1;
  }
  EXCEPT (SocketHTTPServer_Failed)
  {
    fprintf (stderr, "Server error\n");
    result = 1;
  }
  FINALLY
  {
    if (server)
      {
        SocketHTTPServer_free (&server);
      }
  }
  END_TRY;

  return result;
}

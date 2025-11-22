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
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

#define BENCH_PORT 8080
#define BENCH_BUF_SIZE 8192

static volatile int server_running = 1;

static void
signal_handler (int sig)
{
  (void)sig;
  server_running = 0;
}

/* Echo handler for accepted connection - non-blocking */
static void
handle_echo_connection (SocketPoll_T poll, Socket_T client)
{
  char buf[BENCH_BUF_SIZE];
  ssize_t n;
  int fd = Socket_fd (client);

  if (fd < 0)
    return; /* Already closed */

  TRY
  {
    /* Read available data (non-blocking) */
    n = Socket_recv (client, buf, sizeof (buf));
    if (n > 0)
      {
        /* Echo back what we received */
        Socket_sendall (client, buf, n);
      }
    /* n == 0 means EAGAIN/EWOULDBLOCK - no data available, just return */
    /* EOF will raise Socket_Closed exception */
  }
  EXCEPT (Socket_Closed)
  {
    /* Client closed connection - remove from poll and free */
    if (fd >= 0)
      {
        SocketPoll_del (poll, client);
      }
    Socket_free (&client);
  }
  EXCEPT (Socket_Failed)
  {
    /* Error - remove from poll and free */
    if (fd >= 0)
      {
        SocketPoll_del (poll, client);
      }
    Socket_free (&client);
  }
  END_TRY;
}

/* Main server using SocketPoll */
int
main (int argc, char **argv)
{
  volatile int port = BENCH_PORT;

  // Parse args (simple: --port=8080)
  for (int i = 1; i < argc; i++)
    {
      if (strncmp (argv[i], "--port=", 7) == 0)
        port = atoi (argv[i] + 7);
    }

  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  Arena_T arena = Arena_new ();
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Socket_bind (server, "127.0.0.1", port);
    // Check if bind succeeded (Socket_bind may return gracefully on errors)
    if (!Socket_isbound (server))
      {
        fprintf (stderr, "Failed to bind to port %d (errno: %d - %s)\n", port,
                 errno, strerror (errno));
        return 1;
      }
    Socket_listen (server, SOMAXCONN);
    Socket_setnonblocking (server);

    SocketPoll_T poll = SocketPoll_new (4096);
    SocketPoll_add (poll, server, POLL_READ, NULL);

    printf ("Benchmark server listening on port %d\n", port);

    while (server_running)
      {
        SocketEvent_T *events;
        int n = SocketPoll_wait (poll, &events, 100); // 100ms timeout

        for (int i = 0; i < n; i++)
          {
            Socket_T sock = events[i].socket;
            int fd = Socket_fd (sock);

            if (sock == server)
              {
                /* Accept new connections */
                Socket_T client;
                while ((client = Socket_accept (server)) != NULL)
                  {
                    int client_fd = Socket_fd (client);
                    if (client_fd >= 0)
                      {
                        Socket_setnonblocking (
                            client); /* Ensure non-blocking */
                        SocketPoll_add (poll, client, POLL_READ, NULL);
                      }
                    else
                      {
                        Socket_free (&client);
                      }
                  }
              }
            else if (fd >= 0 && (events[i].events & POLL_READ))
              {
                /* Handle data from client */
                handle_echo_connection (poll, sock);
              }
            else
              {
                // Socket already freed or invalid FD - skip
                continue;
              }
          }
      }

    SocketPoll_free (&poll);
    Socket_free (&server);
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "Server error\n");
    return 1;
  }
  FINALLY { Arena_dispose (&arena); }
  END_TRY;

  return 0;
}

/**
 * graceful_shutdown.c - Production-grade signal handling example
 *
 * Demonstrates async-signal-safe shutdown patterns:
 * - Self-pipe trick for signal notification
 * - Integration with SocketPoll event loop (using poll timeout)
 * - Graceful connection draining with timeout
 * - Clean resource cleanup
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_graceful_shutdown
 *
 * Usage:
 *   ./example_graceful_shutdown [port]
 *
 * Test:
 *   1. Start server: ./example_graceful_shutdown 8080
 *   2. Connect clients: nc localhost 8080
 *   3. Send SIGINT (Ctrl+C) or SIGTERM to initiate graceful shutdown
 *   4. Observe connections draining before exit
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "poll/SocketPoll.h"
#include "pool/SocketPool.h"
#include "socket/Socket.h"

/* =============================================================================
 * Configuration
 * ============================================================================= */

#define DEFAULT_PORT 8080
#define MAX_CONNECTIONS 100
#define BUFFER_SIZE 4096
#define DRAIN_TIMEOUT_MS 30000 /* 30 seconds */
#define POLL_TIMEOUT_MS 100    /* 100ms - short to check signal pipe */

/* =============================================================================
 * Global State (Signal-Safe)
 * ============================================================================= */

/* Self-pipe file descriptors for async-signal-safe notification */
static int g_signal_pipe[2] = { -1, -1 };

/* Signal that was received (for logging after handler returns) */
static volatile sig_atomic_t g_last_signal = 0;

/* =============================================================================
 * Signal Handler (Async-Signal-Safe)
 * ============================================================================= */

/**
 * signal_handler - Async-signal-safe signal handler
 *
 * ONLY performs async-signal-safe operations:
 * - Saves errno
 * - Writes to pipe (write() is async-signal-safe)
 * - Restores errno
 *
 * The signal number is written to the pipe so the main loop can
 * determine which signal was received.
 */
static void
signal_handler (int signo)
{
  int saved_errno = errno;

  g_last_signal = signo;

  /* Write signal number to pipe - write() is async-signal-safe */
  char byte = (char)signo;
  ssize_t ret = write (g_signal_pipe[1], &byte, 1);
  (void)ret; /* Ignore - best effort in signal handler */

  errno = saved_errno;
}

/* =============================================================================
 * Signal Infrastructure Setup
 * ============================================================================= */

/**
 * setup_signal_handling - Initialize signal handling infrastructure
 *
 * Creates the self-pipe and installs signal handlers for:
 * - SIGINT  (Ctrl+C)
 * - SIGTERM (kill default)
 * - SIGHUP  (optional: config reload, but we use for shutdown too)
 *
 * Returns: 0 on success, -1 on error
 */
static int
setup_signal_handling (void)
{
  /* Create self-pipe */
  if (pipe (g_signal_pipe) < 0)
    {
      perror ("pipe");
      return -1;
    }

  /* Make both ends non-blocking to prevent blocking in signal handler */
  if (fcntl (g_signal_pipe[0], F_SETFL, O_NONBLOCK) < 0
      || fcntl (g_signal_pipe[1], F_SETFL, O_NONBLOCK) < 0)
    {
      perror ("fcntl O_NONBLOCK");
      close (g_signal_pipe[0]);
      close (g_signal_pipe[1]);
      return -1;
    }

  /* Set close-on-exec to prevent leaking to child processes */
  fcntl (g_signal_pipe[0], F_SETFD, FD_CLOEXEC);
  fcntl (g_signal_pipe[1], F_SETFD, FD_CLOEXEC);

  /* Install signal handlers using sigaction (not signal()) */
  struct sigaction sa;
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART; /* Restart interrupted syscalls */

  if (sigaction (SIGINT, &sa, NULL) < 0)
    {
      perror ("sigaction SIGINT");
      return -1;
    }

  if (sigaction (SIGTERM, &sa, NULL) < 0)
    {
      perror ("sigaction SIGTERM");
      return -1;
    }

  if (sigaction (SIGHUP, &sa, NULL) < 0)
    {
      perror ("sigaction SIGHUP");
      return -1;
    }

  return 0;
}

/**
 * check_signal_pipe - Check if signal pipe has data (non-blocking)
 *
 * Returns: 1 if signal received, 0 otherwise
 */
static int
check_signal_pipe (void)
{
  char buf[16];
  ssize_t n = read (g_signal_pipe[0], buf, sizeof (buf));
  return (n > 0) ? 1 : 0;
}

/**
 * cleanup_signal_handling - Clean up signal infrastructure
 */
static void
cleanup_signal_handling (void)
{
  if (g_signal_pipe[0] >= 0)
    close (g_signal_pipe[0]);
  if (g_signal_pipe[1] >= 0)
    close (g_signal_pipe[1]);
  g_signal_pipe[0] = -1;
  g_signal_pipe[1] = -1;
}

/* =============================================================================
 * Connection Handling
 * ============================================================================= */

/**
 * handle_client_data - Process data from a client connection
 *
 * Simple echo server: reads data and echoes it back.
 * Returns: 1 to keep connection, 0 to close
 */
static int
handle_client_data (Socket_T client, SocketBuf_T inbuf, SocketBuf_T outbuf)
{
  char buf[BUFFER_SIZE];
  ssize_t n;

  (void)inbuf;
  (void)outbuf;

  TRY
  {
    n = Socket_recv (client, buf, sizeof (buf) - 1);
    if (n > 0)
      {
        buf[n] = '\0';
        printf ("[%s:%d] Received %zd bytes\n", Socket_getpeeraddr (client),
                Socket_getpeerport (client), n);

        /* Echo back */
        Socket_sendall (client, buf, n);
        return 1; /* Keep connection */
      }
  }
  EXCEPT (Socket_Closed)
  {
    printf ("[%s:%d] Client disconnected\n", Socket_getpeeraddr (client),
            Socket_getpeerport (client));
  }
  EXCEPT (Socket_Failed)
  {
    printf ("[%s:%d] Socket error: %s\n", Socket_getpeeraddr (client),
            Socket_getpeerport (client), Socket_GetLastError ());
  }
  END_TRY;

  return 0; /* Close connection */
}

/* =============================================================================
 * Main Server
 * ============================================================================= */

int
main (int argc, char *argv[])
{
  /* Variables used across TRY/EXCEPT must be volatile to avoid clobbering */
  volatile int port = DEFAULT_PORT;
  Socket_T server = NULL;
  SocketPoll_T poll = NULL;
  SocketPool_T pool = NULL;
  Arena_T arena = NULL;
  int running = 1;

  /* Parse command line */
  if (argc > 1)
    {
      port = atoi (argv[1]);
      if (port <= 0 || port > 65535)
        {
          fprintf (stderr, "Invalid port: %s\n", argv[1]);
          return 1;
        }
    }

  /* Setup signal handling infrastructure */
  if (setup_signal_handling () < 0)
    {
      fprintf (stderr, "Failed to setup signal handling\n");
      return 1;
    }

  printf ("=== Graceful Shutdown Example ===\n");
  printf ("Press Ctrl+C or send SIGTERM to initiate graceful shutdown\n\n");

  TRY
  {
    /* Create resources */
    arena = Arena_new ();
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    poll = SocketPoll_new (MAX_CONNECTIONS + 10);
    pool = SocketPool_new (arena, MAX_CONNECTIONS, BUFFER_SIZE);

    /* Configure and bind server */
    Socket_setreuseaddr (server);
    Socket_bind (server, NULL, port);
    Socket_listen (server, 128);
    Socket_setnonblocking (server);

    printf ("Server listening on port %d\n", port);
    printf ("Drain timeout: %d seconds\n\n", DRAIN_TIMEOUT_MS / 1000);

    /* Add server socket to poll */
    SocketPoll_add (poll, server, POLL_READ, server);

    /* Main event loop
     *
     * Note: We use a short poll timeout and check the signal pipe
     * separately. This is because SocketPoll only supports Socket_T,
     * not raw file descriptors. For more sophisticated integration,
     * you could use poll()/select() directly for both.
     */
    while (running)
      {
        /* Check signal pipe first (non-blocking) */
        if (check_signal_pipe ())
          {
            printf ("\n[SIGNAL] Received signal %d, initiating graceful "
                    "shutdown...\n",
                    (int)g_last_signal);
            running = 0;
            break;
          }

        /* Poll for socket events with short timeout */
        SocketEvent_T *events;
        int nevents = SocketPoll_wait (poll, &events, POLL_TIMEOUT_MS);

        for (int i = 0; i < nevents && running; i++)
          {
            /* Check for new connections */
            if (events[i].socket == server)
              {
                Socket_T client = Socket_accept (server);
                if (client)
                  {
                    Socket_setnonblocking (client);
                    Connection_T conn = SocketPool_add (pool, client);
                    if (conn)
                      {
                        SocketPoll_add (poll, client, POLL_READ, conn);
                        printf ("[%s:%d] Client connected (total: %zu)\n",
                                Socket_getpeeraddr (client),
                                Socket_getpeerport (client),
                                SocketPool_count (pool));
                      }
                    else
                      {
                        printf ("Pool full, rejecting connection\n");
                        Socket_free (&client);
                      }
                  }
                continue;
              }

            /* Handle client data */
            Connection_T conn = events[i].data;
            if (conn)
              {
                Socket_T client = Connection_socket (conn);
                SocketBuf_T inbuf = Connection_inbuf (conn);
                SocketBuf_T outbuf = Connection_outbuf (conn);

                if (!handle_client_data (client, inbuf, outbuf))
                  {
                    /* Close connection */
                    SocketPoll_del (poll, client);
                    SocketPool_remove (pool, client);
                    Socket_free (&client);
                    printf ("Connections remaining: %zu\n",
                            SocketPool_count (pool));
                  }
              }
          }
      }

    /* =========================================================================
     * Graceful Shutdown Phase
     * ========================================================================= */

    printf ("\n=== Graceful Shutdown ===\n");
    printf ("Active connections: %zu\n", SocketPool_count (pool));

    /* Stop accepting new connections */
    SocketPoll_del (poll, server);
    Socket_free (&server);
    server = NULL;
    printf ("Stopped accepting new connections\n");

    /* Initiate drain with timeout */
    if (SocketPool_count (pool) > 0)
      {
        printf ("Draining %zu connections (timeout: %ds)...\n",
                SocketPool_count (pool), DRAIN_TIMEOUT_MS / 1000);

        SocketPool_drain (pool, DRAIN_TIMEOUT_MS);

        /* Continue processing events until drain completes */
        while (SocketPool_drain_poll (pool) > 0)
          {
            SocketEvent_T *events;
            int timeout = SocketPool_drain_remaining_ms (pool);
            if (timeout <= 0)
              timeout = 100;

            int nevents = SocketPoll_wait (poll, &events, timeout);

            for (int i = 0; i < nevents; i++)
              {
                Connection_T conn = events[i].data;
                if (conn)
                  {
                    Socket_T client = Connection_socket (conn);
                    SocketBuf_T inbuf = Connection_inbuf (conn);
                    SocketBuf_T outbuf = Connection_outbuf (conn);

                    /* Process remaining data, then close */
                    handle_client_data (client, inbuf, outbuf);

                    SocketPoll_del (poll, client);
                    SocketPool_remove (pool, client);
                    Socket_free (&client);

                    printf ("Drained connection (remaining: %zu)\n",
                            SocketPool_count (pool));
                  }
              }
          }

        size_t remaining = SocketPool_count (pool);
        if (remaining > 0)
          {
            printf ("Drain timeout - force closing %zu connections\n",
                    remaining);
            SocketPool_drain_force (pool);
          }
        else
          {
            printf ("All connections drained gracefully\n");
          }
      }
    else
      {
        printf ("No connections to drain\n");
      }
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "Socket error: %s\n", Socket_GetLastError ());
  }
  EXCEPT (SocketPoll_Failed)
  {
    fprintf (stderr, "Poll error: %s\n", Socket_GetLastError ());
  }
  EXCEPT (SocketPool_Failed)
  {
    fprintf (stderr, "Pool error: %s\n", Socket_GetLastError ());
  }
  END_TRY;

  /* Cleanup */
  printf ("\n=== Cleanup ===\n");

  if (server)
    {
      Socket_free (&server);
      printf ("Server socket closed\n");
    }

  if (pool)
    {
      SocketPool_free (&pool);
      printf ("Connection pool freed\n");
    }

  if (poll)
    {
      SocketPoll_free (&poll);
      printf ("Poll instance freed\n");
    }

  if (arena)
    {
      Arena_dispose (&arena);
      printf ("Arena disposed\n");
    }

  cleanup_signal_handling ();
  printf ("Signal handling cleaned up\n");

  printf ("\nGraceful shutdown complete.\n");
  return 0;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * async_io.c - Asynchronous I/O Example
 *
 * Demonstrates the SocketAsync API for high-performance asynchronous I/O:
 * - Creating async context with SocketAsync_new()
 * - Submitting async send operations with SocketAsync_send()
 * - Submitting async receive operations with SocketAsync_recv()
 * - Processing completions with SocketAsync_process_completions()
 * - Polling for completion status with SocketAsync_poll()
 * - Using completion callbacks for notification
 * - Integration with SocketPoll event loop
 * - Backend detection and capability checking
 * - Batch submission for improved throughput
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_async_io
 *
 * Usage:
 *   ./example_async_io [mode] [host] [port]
 *   ./example_async_io standalone localhost 8080
 *   ./example_async_io integrated localhost 8080
 *
 * Modes:
 *   standalone - Standalone async context with manual completion processing
 *   integrated - Integrated with SocketPoll for automatic completion handling
 *
 * Test server setup:
 *   # Terminal 1: Start echo server
 *   nc -l 8080
 *
 *   # Terminal 2: Run this example
 *   ./example_async_io standalone localhost 8080
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"

/* =============================================================================
 * Configuration
 * =============================================================================
 */

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT 8080
#define BUFFER_SIZE 4096
#define NUM_MESSAGES 5
#define COMPLETION_TIMEOUT_MS 100

/* =============================================================================
 * Async Operation State
 * =============================================================================
 */

/**
 * User data structure passed to async callbacks
 * Tracks state for partial transfers and multiple operations
 */
typedef struct AsyncState
{
  Socket_T socket;
  char *buffer;
  size_t total_len;
  size_t completed;
  int message_num;
  int is_send;
  SocketAsync_T async;
} AsyncState;

/* Statistics for demo */
static struct
{
  int sends_completed;
  int recvs_completed;
  int total_bytes_sent;
  int total_bytes_received;
  int errors;
} g_stats = { 0, 0, 0, 0, 0 };

/* =============================================================================
 * Async Callbacks
 * =============================================================================
 */

/**
 * send_callback - Called when async send completes
 *
 * Handles send completion, partial transfers, and errors.
 */
static void
send_callback (Socket_T socket, ssize_t bytes, int err, void *user_data)
{
  AsyncState *state = (AsyncState *)user_data;

  if (err != 0)
    {
      printf ("[FAIL] Send error for message #%d: %s (err=%d)\n",
              state->message_num, strerror (err), err);
      g_stats.errors++;
      free (state->buffer);
      free (state);
      return;
    }

  if (bytes <= 0)
    {
      printf ("[FAIL] Send returned %zd bytes for message #%d\n", bytes,
              state->message_num);
      g_stats.errors++;
      free (state->buffer);
      free (state);
      return;
    }

  state->completed += bytes;
  g_stats.total_bytes_sent += bytes;

  /* Check for partial transfer */
  if (state->completed < state->total_len)
    {
      printf ("[INFO] Partial send: %zu/%zu bytes for message #%d\n",
              state->completed, state->total_len, state->message_num);

      /* Resubmit remaining data */
      const void *remaining_buf
          = (const char *)state->buffer + state->completed;
      size_t remaining = state->total_len - state->completed;

      unsigned req_id
          = SocketAsync_send (state->async, socket, remaining_buf, remaining,
                              send_callback, state, ASYNC_FLAG_NONE);

      if (req_id == 0)
        {
          printf ("[FAIL] Failed to resubmit partial send\n");
          g_stats.errors++;
          free (state->buffer);
          free (state);
        }
      return;
    }

  /* Complete transfer */
  printf ("[OK] Send completed: %zu bytes for message #%d\n", state->completed,
          state->message_num);
  g_stats.sends_completed++;

  free (state->buffer);
  free (state);
}

/**
 * recv_callback - Called when async receive completes
 *
 * Handles received data, EOF, and errors.
 */
static void
recv_callback (Socket_T socket, ssize_t bytes, int err, void *user_data)
{
  AsyncState *state = (AsyncState *)user_data;

  if (err != 0)
    {
      printf ("[FAIL] Receive error: %s (err=%d)\n", strerror (err), err);
      g_stats.errors++;
      free (state->buffer);
      free (state);
      return;
    }

  if (bytes == 0)
    {
      printf ("[INFO] EOF - connection closed gracefully\n");
      free (state->buffer);
      free (state);
      return;
    }

  if (bytes < 0)
    {
      printf ("[FAIL] Receive returned negative bytes: %zd\n", bytes);
      g_stats.errors++;
      free (state->buffer);
      free (state);
      return;
    }

  /* Successfully received data */
  state->completed += bytes;
  g_stats.total_bytes_received += bytes;

  /* Null-terminate for printing (safe because we allocated extra byte) */
  state->buffer[state->completed] = '\0';

  printf ("[OK] Received %zd bytes: %.50s%s\n", bytes, state->buffer,
          state->completed > 50 ? "..." : "");
  g_stats.recvs_completed++;

  /* For demo purposes, we'll submit another recv if we haven't received
   * enough data yet. In a real application, you'd parse protocol messages. */
  if (state->message_num < NUM_MESSAGES)
    {
      /* Reset for next receive */
      state->completed = 0;
      state->message_num++;

      unsigned req_id
          = SocketAsync_recv (state->async, socket, state->buffer, BUFFER_SIZE,
                              recv_callback, state, ASYNC_FLAG_NONE);

      if (req_id == 0)
        {
          printf ("[FAIL] Failed to submit next receive\n");
          g_stats.errors++;
          free (state->buffer);
          free (state);
        }
    }
  else
    {
      /* Done receiving */
      free (state->buffer);
      free (state);
    }
}

/* =============================================================================
 * Standalone Mode - Manual Completion Processing
 * =============================================================================
 */

/**
 * demo_standalone - Demonstrates standalone async context
 *
 * Creates a standalone SocketAsync_T context and manually processes
 * completions in a loop. Useful for custom event loops or testing.
 */
static int
demo_standalone (const char *host, int port)
{
  Arena_T arena = NULL;
  SocketAsync_T async = NULL;
  Socket_T sock = NULL;
  volatile int result = 0;

  printf ("\n=== Standalone Async I/O Demo ===\n\n");

  TRY
  {
    /* Create arena for memory management */
    arena = Arena_new ();

    /* Create standalone async context */
    printf ("[INFO] Creating standalone async context...\n");
    async = SocketAsync_new (arena);

    /* Check backend availability */
    const char *backend = SocketAsync_backend_name (async);
    int is_available = SocketAsync_is_available (async);

    printf ("[INFO] Backend: %s\n", backend);
    printf ("[INFO] Native async available: %s\n",
            is_available ? "yes" : "no (fallback mode)");

    if (!is_available)
      {
        printf ("[WARN] Fallback mode active - manual I/O required in "
                "event handlers\n");
      }

    /* Check specific backend availability */
    if (SocketAsync_backend_available (ASYNC_BACKEND_IO_URING))
      {
        printf ("[INFO] io_uring backend is available\n");
      }
    else if (SocketAsync_backend_available (ASYNC_BACKEND_KQUEUE))
      {
        printf ("[INFO] kqueue backend is available\n");
      }

    /* Create and connect socket */
    printf ("[INFO] Connecting to %s:%d...\n", host, port);
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_connect (sock, host, port);
    printf ("[OK] Connected!\n\n");

    /* Submit multiple async send operations */
    printf ("[INFO] Submitting %d async send operations...\n", NUM_MESSAGES);

    for (int i = 0; i < NUM_MESSAGES; i++)
      {
        /* Allocate state for this operation */
        AsyncState *state = malloc (sizeof (AsyncState));
        if (!state)
          {
            printf ("[FAIL] Failed to allocate state\n");
            continue;
          }

        /* Prepare message */
        state->buffer = malloc (BUFFER_SIZE);
        if (!state->buffer)
          {
            free (state);
            continue;
          }

        snprintf (state->buffer, BUFFER_SIZE,
                  "Message #%d from async_io example\n", i + 1);
        state->total_len = strlen (state->buffer);
        state->completed = 0;
        state->message_num = i + 1;
        state->is_send = 1;
        state->socket = sock;
        state->async = async;

        /* Submit async send */
        unsigned req_id
            = SocketAsync_send (async, sock, state->buffer, state->total_len,
                                send_callback, state, ASYNC_FLAG_NONE);

        if (req_id == 0)
          {
            printf ("[FAIL] Failed to submit send #%d\n", i + 1);
            free (state->buffer);
            free (state);
            g_stats.errors++;
          }
        else
          {
            printf ("[INFO] Submitted send #%d (req_id=%u)\n", i + 1, req_id);
          }
      }

    /* Submit initial async receive */
    printf ("\n[INFO] Submitting async receive operation...\n");

    AsyncState *recv_state = malloc (sizeof (AsyncState));
    if (recv_state)
      {
        recv_state->buffer = malloc (BUFFER_SIZE + 1); /* +1 for null term */
        if (recv_state->buffer)
          {
            recv_state->total_len = BUFFER_SIZE;
            recv_state->completed = 0;
            recv_state->message_num = 1;
            recv_state->is_send = 0;
            recv_state->socket = sock;
            recv_state->async = async;

            unsigned req_id = SocketAsync_recv (
                async, sock, recv_state->buffer, BUFFER_SIZE, recv_callback,
                recv_state, ASYNC_FLAG_NONE);

            if (req_id == 0)
              {
                printf ("[FAIL] Failed to submit receive\n");
                free (recv_state->buffer);
                free (recv_state);
                g_stats.errors++;
              }
            else
              {
                printf ("[INFO] Submitted receive (req_id=%u)\n\n", req_id);
              }
          }
        else
          {
            free (recv_state);
          }
      }

    /* Main loop: Process completions manually */
    printf ("[INFO] Processing completions (manual mode)...\n");

    int iterations = 0;
    const int max_iterations = 100; /* Safety limit */

    while (iterations < max_iterations)
      {
        /* Process completions with timeout */
        int processed
            = SocketAsync_process_completions (async, COMPLETION_TIMEOUT_MS);

        if (processed < 0)
          {
            printf ("[FAIL] Completion processing failed: %s\n",
                    strerror (errno));
            result = 1;
            break;
          }
        else if (processed > 0)
          {
            printf ("[INFO] Processed %d completions\n", processed);
          }

        /* Check if we're done */
        if (g_stats.sends_completed >= NUM_MESSAGES
            && g_stats.recvs_completed >= NUM_MESSAGES)
          {
            printf ("\n[OK] All operations completed!\n");
            break;
          }

        iterations++;
        usleep (10000); /* 10ms between iterations */
      }

    if (iterations >= max_iterations)
      {
        printf ("[WARN] Max iterations reached\n");
      }

    /* Print statistics */
    printf ("\n=== Statistics ===\n");
    printf ("Sends completed:  %d/%d\n", g_stats.sends_completed,
            NUM_MESSAGES);
    printf ("Recvs completed:  %d/%d\n", g_stats.recvs_completed,
            NUM_MESSAGES);
    printf ("Total bytes sent: %d\n", g_stats.total_bytes_sent);
    printf ("Total bytes rcvd: %d\n", g_stats.total_bytes_received);
    printf ("Errors:           %d\n", g_stats.errors);

    if (g_stats.errors == 0 && g_stats.sends_completed == NUM_MESSAGES)
      {
        printf ("\n[OK] Standalone demo completed successfully!\n");
      }
    else
      {
        printf ("\n[WARN] Standalone demo completed with warnings\n");
      }
  }
  EXCEPT (SocketAsync_Failed)
  {
    fprintf (stderr, "[FAIL] Async I/O error\n");
    result = 1;
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "[FAIL] Socket error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (sock)
    Socket_free (&sock);
  if (async)
    SocketAsync_free (&async);
  if (arena)
    Arena_dispose (&arena);

  return result;
}

/* =============================================================================
 * Integrated Mode - SocketPoll Integration
 * =============================================================================
 */

/**
 * demo_integrated - Demonstrates SocketPoll-integrated async I/O
 *
 * Uses SocketPoll_get_async() to obtain an async context that automatically
 * processes completions during SocketPoll_wait(). This is the recommended
 * approach for production event-driven applications.
 */
static int
demo_integrated (const char *host, int port)
{
  SocketPoll_T poll = NULL;
  SocketAsync_T async = NULL;
  Socket_T sock = NULL;
  volatile int result = 0;

  printf ("\n=== Integrated Async I/O Demo (SocketPoll) ===\n\n");

  /* Reset stats */
  memset (&g_stats, 0, sizeof (g_stats));

  TRY
  {
    /* Create SocketPoll instance */
    printf ("[INFO] Creating SocketPoll instance...\n");
    poll = SocketPoll_new (128);

    /* Get integrated async context */
    printf ("[INFO] Getting integrated async context...\n");
    async = SocketPoll_get_async (poll);

    if (!async)
      {
        printf ("[WARN] SocketPoll does not provide async context\n");
        printf ("[INFO] Async I/O may not be available on this platform\n");
        result = 1;
        goto cleanup;
      }

    /* Check backend */
    const char *backend = SocketAsync_backend_name (async);
    int is_available = SocketAsync_is_available (async);

    printf ("[INFO] Backend: %s\n", backend);
    printf ("[INFO] Native async: %s\n",
            is_available ? "yes" : "no (fallback)");

    /* Create and connect socket */
    printf ("[INFO] Connecting to %s:%d...\n", host, port);
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_connect (sock, host, port);
    printf ("[OK] Connected!\n\n");

    /* Demonstrate batch submission */
    printf ("[INFO] Demonstrating batch submission of async operations...\n");

    /* Allocate batch array */
    SocketAsync_Op *ops = malloc (sizeof (SocketAsync_Op) * NUM_MESSAGES);
    if (!ops)
      {
        printf ("[FAIL] Failed to allocate batch array\n");
        result = 1;
        goto cleanup;
      }

    /* Prepare batch operations */
    AsyncState **states = malloc (sizeof (AsyncState *) * NUM_MESSAGES);
    if (!states)
      {
        free (ops);
        printf ("[FAIL] Failed to allocate states array\n");
        result = 1;
        goto cleanup;
      }

    for (int i = 0; i < NUM_MESSAGES; i++)
      {
        states[i] = malloc (sizeof (AsyncState));
        states[i]->buffer = malloc (BUFFER_SIZE);
        snprintf (states[i]->buffer, BUFFER_SIZE,
                  "Batch message #%d from integrated demo\n", i + 1);
        states[i]->total_len = strlen (states[i]->buffer);
        states[i]->completed = 0;
        states[i]->message_num = i + 1;
        states[i]->is_send = 1;
        states[i]->socket = sock;
        states[i]->async = async;

        /* Prepare operation descriptor */
        ops[i].socket = sock;
        ops[i].is_send = 1;
        ops[i].send_buf = states[i]->buffer;
        ops[i].recv_buf = NULL;
        ops[i].len = states[i]->total_len;
        ops[i].cb = send_callback;
        ops[i].user_data = states[i];
        ops[i].flags = ASYNC_FLAG_NONE;
        ops[i].request_id = 0;
      }

    /* Submit batch */
    int submitted = SocketAsync_submit_batch (async, ops, NUM_MESSAGES);
    printf ("[INFO] Submitted %d/%d operations in batch\n", submitted,
            NUM_MESSAGES);

    for (int i = 0; i < submitted; i++)
      {
        printf ("[INFO] Operation #%d assigned request_id=%u\n", i + 1,
                ops[i].request_id);
      }

    free (ops);
    free (states);

    /* Note: In integrated mode, completions are automatically processed
     * during SocketPoll_wait(). For this demo, we'll just sleep to allow
     * async operations to complete. In a real application, you'd be
     * handling socket events in the poll loop. */

    printf ("\n[INFO] Completions will be processed automatically by "
            "SocketPoll\n");
    printf ("[INFO] Waiting for operations to complete...\n");

    /* Simple wait loop - in real app, this would be your event loop */
    int iterations = 0;
    while (iterations < 50 && g_stats.sends_completed < submitted)
      {
        /* Process completions (normally done during SocketPoll_wait) */
        int processed
            = SocketAsync_process_completions (async, COMPLETION_TIMEOUT_MS);

        if (processed > 0)
          {
            printf ("[INFO] Processed %d completions\n", processed);
          }

        iterations++;
        usleep (50000); /* 50ms */
      }

    printf ("\n[OK] Integrated demo completed!\n");

    /* Print statistics */
    printf ("\n=== Statistics ===\n");
    printf ("Sends completed:  %d/%d\n", g_stats.sends_completed, submitted);
    printf ("Total bytes sent: %d\n", g_stats.total_bytes_sent);
    printf ("Errors:           %d\n", g_stats.errors);
  }
  EXCEPT (SocketAsync_Failed)
  {
    fprintf (stderr, "[FAIL] Async I/O error\n");
    result = 1;
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "[FAIL] Socket error\n");
    result = 1;
  }
  END_TRY;

cleanup:
  /* Cleanup - async is owned by poll, so don't free it separately */
  if (sock)
    Socket_free (&sock);
  if (poll)
    SocketPoll_free (&poll);

  return result;
}

/* =============================================================================
 * Main Entry Point
 * =============================================================================
 */

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile mode = "standalone";
  const char *volatile host = DEFAULT_HOST;
  volatile int port = DEFAULT_PORT;

  /* Parse command line arguments */
  if (argc > 1)
    mode = argv[1];
  if (argc > 2)
    host = argv[2];
  if (argc > 3)
    port = atoi (argv[3]);

  if (port <= 0 || port > 65535)
    {
      fprintf (stderr, "Invalid port: %d\n", port);
      return 1;
    }

  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  printf ("Asynchronous I/O Example\n");
  printf ("========================\n");
  printf ("Mode: %s\n", mode);
  printf ("Target: %s:%d\n\n", host, port);

  /* Run appropriate demo */
  if (strcmp (mode, "integrated") == 0)
    {
      return demo_integrated (host, port);
    }
  else
    {
      return demo_standalone (host, port);
    }
}

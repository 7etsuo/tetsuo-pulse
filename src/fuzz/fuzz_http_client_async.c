/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http_client_async.c - HTTP Client Async I/O State Machine Fuzzer
 *
 * Targets SocketHTTPClient-async.c (2% coverage → goal: 80%+)
 *
 * Fuzzing strategy:
 * - Async I/O initialization with various configs
 * - Send/recv operations with edge case buffer sizes
 * - Async completion callback state machine
 * - Sync/async fallback logic
 * - Concurrent operation submissions
 * - Error handling paths (submission failures, I/O errors)
 * - Memory barriers and volatile state updates
 * - Cleanup during pending operations
 *
 * Key functions under test:
 * - httpclient_async_init()
 * - httpclient_async_cleanup()
 * - httpclient_io_send()
 * - httpclient_io_recv()
 * - async_io_callback() [static, tested indirectly]
 * - wait_for_completion() [static, tested indirectly]
 *
 * Attack surfaces:
 * - Race conditions in async state updates
 * - Use-after-free during cleanup
 * - Buffer overflow in async I/O
 * - NULL pointer dereferences
 * - Memory leaks from incomplete operations
 * - Deadlock in completion wait loop
 *
 * Note: This fuzzer tests the async wrapper logic, not the underlying
 * io_uring implementation (which is tested by fuzz_async.c).
 *
 * Build: CC=clang cmake -B build -DENABLE_FUZZING=ON && cmake --build build
 * --target fuzz_http_client_async Run: ./build/fuzz_http_client_async
 * corpus/http_client_async/ -fork=8 -max_len=4096
 */

#include <stdlib.h>
#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPClient-private.h"
#include "socket/Socket.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Suppress GCC clobbered warnings for TRY/EXCEPT */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Input format for fuzzing */
typedef struct
{
  uint8_t enable_async_io;
  uint8_t enable_pool;
  uint8_t operation_type; /* 0=send, 1=recv, 2=both */
  uint16_t send_size;
  uint16_t recv_size;
  uint8_t error_injection; /* Simulate I/O errors */
  uint8_t cleanup_timing;  /* When to cleanup: 0=after, 1=during */
                           /* Remaining bytes are payload data */
} FuzzInput;

#define MIN_INPUT_SIZE sizeof (FuzzInput)

/**
 * Test async I/O initialization with various configurations
 */
static void
test_async_init_cleanup (Arena_T arena, const FuzzInput *input)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;

  (void)arena; /* Not used in this test */

  SocketHTTPClient_config_defaults (&config);
  config.enable_async_io = input->enable_async_io;
  config.enable_connection_pool = input->enable_pool;

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    /* Test multiple init/cleanup cycles */
    for (int i = 0; i < 3; i++)
      {
        /* Cleanup and re-init */
        httpclient_async_cleanup (client);
        (void)httpclient_async_init (client);
      }

    /* Test cleanup with NULL (should be safe) */
    httpclient_async_cleanup (NULL);

    /* Note: httpclient_async_init(NULL) is not safe - has assertion */

    SocketHTTPClient_free (&client);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected for some configs */
  }
  END_TRY;
}

/**
 * Create a mock socket pair for testing I/O operations
 */
static int
create_socketpair (Socket_T *sock1_out, Socket_T *sock2_out, Arena_T arena)
{
  int fds[2];
  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  (void)arena; /* Not used with Socket_new_from_fd */

  if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) < 0)
    return -1;

  TRY
  {
    sock1 = Socket_new_from_fd (fds[0]);
    sock2 = Socket_new_from_fd (fds[1]);

    *sock1_out = sock1;
    *sock2_out = sock2;
    return 0;
  }
  EXCEPT (Socket_Failed)
  {
    close (fds[0]);
    close (fds[1]);
    return -1;
  }
  END_TRY;

  return -1;
}

/**
 * Test async send operations with various buffer sizes
 */
static void
test_async_send (Arena_T arena,
                 const FuzzInput *input,
                 const uint8_t *payload,
                 size_t payload_len)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;
  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;
  volatile ssize_t sent = 0;

  SocketHTTPClient_config_defaults (&config);
  config.enable_async_io = input->enable_async_io;
  config.enable_connection_pool = 0; /* Simplify for testing */

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    /* Create socket pair for testing */
    if (create_socketpair (&sock1, &sock2, arena) < 0)
      {
        SocketHTTPClient_free (&client);
        RETURN;
      }

    /* Test send with fuzzer payload */
    size_t send_size = input->send_size % (payload_len + 1);
    if (send_size > 0 && send_size <= payload_len)
      {
        sent = httpclient_io_send (client, sock1, payload, send_size);
        /* Verify result is reasonable */
        if (sent > 0)
          {
            assert ((size_t)sent <= send_size);
          }
      }

    /* Test edge cases */
    (void)httpclient_io_send (client, sock1, NULL, 0);    /* Empty send */
    (void)httpclient_io_send (client, sock1, payload, 0); /* Zero length */
    (void)httpclient_io_send (NULL, sock1, payload, 1);   /* NULL client */

    /* Test with invalid socket (should fail gracefully) */
    (void)httpclient_io_send (client, NULL, payload, 1);

    SocketHTTPClient_free (&client);
    Socket_free (&sock1);
    Socket_free (&sock2);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected */
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected */
  }
  END_TRY;
}

/**
 * Test async recv operations with various buffer sizes
 */
static void
test_async_recv (Arena_T arena, const FuzzInput *input)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;
  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;
  volatile ssize_t recvd = 0;
  uint8_t recv_buf[4096];

  SocketHTTPClient_config_defaults (&config);
  config.enable_async_io = input->enable_async_io;
  config.enable_connection_pool = 0;

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    /* Create socket pair */
    if (create_socketpair (&sock1, &sock2, arena) < 0)
      {
        SocketHTTPClient_free (&client);
        RETURN;
      }

    /* Send some data from sock2 so recv has something to read */
    const char *test_data = "HTTP/1.1 200 OK\r\n\r\n";
    ssize_t written = write (Socket_fd (sock2), test_data, strlen (test_data));
    (void)written;

    /* Test recv with various sizes */
    size_t recv_size = input->recv_size % sizeof (recv_buf);
    if (recv_size > 0)
      {
        recvd = httpclient_io_recv (client, sock1, recv_buf, recv_size);
        if (recvd > 0)
          {
            assert ((size_t)recvd <= recv_size);
          }
      }

    /* Test edge cases */
    (void)httpclient_io_recv (
        client, sock1, NULL, 0); /* NULL buffer with size 0 */
    (void)httpclient_io_recv (client, sock1, recv_buf, 0);  /* Zero length */
    (void)httpclient_io_recv (NULL, sock1, recv_buf, 100);  /* NULL client */
    (void)httpclient_io_recv (client, NULL, recv_buf, 100); /* NULL socket */

    SocketHTTPClient_free (&client);
    Socket_free (&sock1);
    Socket_free (&sock2);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected */
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected */
  }
  END_TRY;
}

/**
 * Test bidirectional async I/O (send + recv)
 */
static void
test_async_bidirectional (Arena_T arena,
                          const FuzzInput *input,
                          const uint8_t *payload,
                          size_t payload_len)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;
  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;
  uint8_t recv_buf[1024];

  SocketHTTPClient_config_defaults (&config);
  config.enable_async_io = input->enable_async_io;
  config.enable_connection_pool = 0;

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    if (create_socketpair (&sock1, &sock2, arena) < 0)
      {
        SocketHTTPClient_free (&client);
        RETURN;
      }

    /* Alternate send and recv operations */
    size_t chunk_size = (payload_len > 0) ? (payload_len / 4 + 1) : 1;
    for (size_t offset = 0; offset < payload_len && offset < 1024;
         offset += chunk_size)
      {
        size_t remaining = payload_len - offset;
        size_t send_len = (remaining < chunk_size) ? remaining : chunk_size;

        /* Send from sock1 */
        if (send_len > 0)
          {
            (void)httpclient_io_send (
                client, sock1, payload + offset, send_len);
          }

        /* Recv on sock2 (direct read to simulate peer) */
        if (send_len > 0)
          {
            (void)read (Socket_fd (sock2), recv_buf, send_len);
          }
      }

    /* Send response from sock2 */
    const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    (void)write (Socket_fd (sock2), response, strlen (response));

    /* Recv response on sock1 */
    (void)httpclient_io_recv (client, sock1, recv_buf, sizeof (recv_buf));

    SocketHTTPClient_free (&client);
    Socket_free (&sock1);
    Socket_free (&sock2);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected */
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected */
  }
  END_TRY;
}

/**
 * Test cleanup during pending operations (stress test)
 */
static void
test_cleanup_during_operations (Arena_T arena, const FuzzInput *input)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;

  (void)arena; /* Not used in this test */

  SocketHTTPClient_config_defaults (&config);
  config.enable_async_io = input->enable_async_io;

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    /* Immediate cleanup (tests cancellation of any pending ops) */
    httpclient_async_cleanup (client);

    /* Re-init */
    (void)httpclient_async_init (client);

    /* Cleanup again */
    httpclient_async_cleanup (client);

    SocketHTTPClient_free (&client);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected */
  }
  END_TRY;
}

/**
 * Test sync fallback when async is unavailable
 */
static void
test_sync_fallback (Arena_T arena, const uint8_t *payload, size_t payload_len)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;
  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;
  uint8_t recv_buf[512];

  /* Explicitly disable async I/O to test fallback path */
  SocketHTTPClient_config_defaults (&config);
  config.enable_async_io = 0;
  config.enable_connection_pool = 0;

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    if (create_socketpair (&sock1, &sock2, arena) < 0)
      {
        SocketHTTPClient_free (&client);
        RETURN;
      }

    /* These should use sync I/O path */
    if (payload_len > 0)
      {
        size_t send_size = payload_len < 512 ? payload_len : 512;
        (void)httpclient_io_send (client, sock1, payload, send_size);
      }

    /* Send response */
    const char *resp = "HTTP/1.1 204 No Content\r\n\r\n";
    (void)write (Socket_fd (sock2), resp, strlen (resp));

    /* Recv should use sync path */
    (void)httpclient_io_recv (client, sock1, recv_buf, sizeof (recv_buf));

    SocketHTTPClient_free (&client);
    Socket_free (&sock1);
    Socket_free (&sock2);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected */
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected */
  }
  END_TRY;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  volatile Arena_T arena = NULL;

  if (size < MIN_INPUT_SIZE)
    return 0;

  /* Copy to aligned local storage to avoid UBSan misaligned access errors.
   * The fuzzer-provided data buffer may not be properly aligned for the
   * struct's uint16_t members. Zero-initialize first to ensure padding
   * bytes are deterministic. */
  FuzzInput input_storage = { 0 };
  memcpy (&input_storage, data, sizeof (FuzzInput));
  const FuzzInput *input = &input_storage;
  const uint8_t *payload = data + MIN_INPUT_SIZE;
  size_t payload_len = size - MIN_INPUT_SIZE;

  TRY
  {
    arena = Arena_new ();
    if (arena == NULL)
      RETURN 0;

    /* Test 1: Init/cleanup cycles */
    test_async_init_cleanup ((Arena_T)arena, input);

    /* Test 2: Async send operations */
    if (payload_len > 0)
      {
        test_async_send ((Arena_T)arena, input, payload, payload_len);
      }

    /* Test 3: Async recv operations */
    test_async_recv ((Arena_T)arena, input);

    /* Test 4: Bidirectional I/O */
    if (payload_len > 0)
      {
        test_async_bidirectional ((Arena_T)arena, input, payload, payload_len);
      }

    /* Test 5: Cleanup stress test */
    test_cleanup_during_operations ((Arena_T)arena, input);

    /* Test 6: Sync fallback path */
    if (payload_len > 0)
      {
        test_sync_fallback ((Arena_T)arena, payload, payload_len);
      }

    Arena_dispose ((Arena_T *)&arena);
  }
  EXCEPT (Arena_Failed)
  {
    if (arena)
      Arena_dispose ((Arena_T *)&arena);
  }
  END_TRY;

  return 0;
}

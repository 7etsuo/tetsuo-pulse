/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_async.c - Fuzzer for SocketAsync module
 *
 * Tests asynchronous I/O operations:
 * - Async context lifecycle (new/free)
 * - Request ID generation and tracking
 * - Send/recv submission (fallback mode)
 * - Request cancellation
 * - Completion processing
 * - Hash table stress testing
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"

/* Suppress GCC clobbered warnings for volatile variables */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types */
typedef enum
{
  OP_LIFECYCLE = 0, /* Create/free async context */
  OP_SEND_SUBMIT,   /* Submit async send */
  OP_RECV_SUBMIT,   /* Submit async recv */
  OP_CANCEL,        /* Cancel operation */
  OP_PROCESS,       /* Process completions */
  OP_MULTI_SUBMIT,  /* Submit multiple requests */
  OP_ACCESSORS,     /* Test accessor functions */
  OP_STRESS_HASH    /* Stress test request hash table */
} AsyncOp;

/* Callback tracking */
static volatile int callback_count = 0;
static volatile ssize_t last_bytes = 0;
static volatile int last_error = 0;

static void
test_callback (Socket_T socket, ssize_t bytes, int err, void *user_data)
{
  (void)socket;
  (void)user_data;
  callback_count++;
  last_bytes = bytes;
  last_error = err;
}

/* Extract values from fuzz data */
static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 8 : 0;
}

static uint16_t
get_uint16 (const uint8_t *data, size_t offset, size_t size)
{
  if (offset + 2 > size)
    return 0;
  return (uint16_t)data[offset] | ((uint16_t)data[offset + 1] << 8);
}

static size_t
get_len (const uint8_t *data, size_t size)
{
  if (size < 3)
    return 64;
  return (data[1] | (data[2] << 8)) % 4096 + 1;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  Arena_T arena = NULL;
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile uint8_t op = get_op (data, size);
  volatile unsigned request_ids[32] = { 0 };
  volatile int num_requests = 0;
  char send_buf[1024];
  char recv_buf[1024];

  /* Initialize send buffer with fuzz data */
  size_t copy_len = size > sizeof (send_buf) ? sizeof (send_buf) : size;
  memcpy (send_buf, data, copy_len);

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      {
        return 0;
      }

    switch (op)
      {
      case OP_LIFECYCLE:
        {
          /* Test async context lifecycle */
          async = SocketAsync_new (arena);

          /* Test accessors */
          (void)SocketAsync_is_available (async);
          (void)SocketAsync_backend_name (async);

          /* Free and recreate */
          SocketAsync_free (&async);
          assert (async == NULL);

          async = SocketAsync_new (arena);
          SocketAsync_free (&async);
        }
        break;

      case OP_SEND_SUBMIT:
        {
          /* Create async context and socket for send test */
          async = SocketAsync_new (arena);

          /* Create a socket (will fail to connect but that's OK for fuzzing)
           */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Submit async send - will queue in fallback mode */
          size_t len = get_len (data, size);
          if (len > sizeof (send_buf))
            len = sizeof (send_buf);

          unsigned req_id
              = SocketAsync_send (async, socket, send_buf, len, test_callback,
                                  NULL, ASYNC_FLAG_NONE);

          /* Cancel if we got a request ID */
          if (req_id > 0)
            SocketAsync_cancel (async, req_id);

          Socket_free (&socket);
          SocketAsync_free (&async);
        }
        break;

      case OP_RECV_SUBMIT:
        {
          /* Create async context and socket for recv test */
          async = SocketAsync_new (arena);
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Submit async recv */
          size_t len = get_len (data, size);
          if (len > sizeof (recv_buf))
            len = sizeof (recv_buf);

          unsigned req_id
              = SocketAsync_recv (async, socket, recv_buf, len, test_callback,
                                  NULL, ASYNC_FLAG_NONE);

          if (req_id > 0)
            SocketAsync_cancel (async, req_id);

          Socket_free (&socket);
          SocketAsync_free (&async);
        }
        break;

      case OP_CANCEL:
        {
          /* Test cancel with various request IDs */
          async = SocketAsync_new (arena);
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Submit a request */
          unsigned req_id
              = SocketAsync_send (async, socket, send_buf, 64, test_callback,
                                  NULL, ASYNC_FLAG_NONE);

          /* Cancel with valid ID */
          if (req_id > 0)
            {
              int result = SocketAsync_cancel (async, req_id);
              (void)result;
            }

          /* Cancel with invalid IDs */
          SocketAsync_cancel (async, 0);
          SocketAsync_cancel (async, 0xFFFFFFFF);
          SocketAsync_cancel (async, get_uint16 (data, 3, size));

          Socket_free (&socket);
          SocketAsync_free (&async);
        }
        break;

      case OP_PROCESS:
        {
          /* Test completion processing */
          async = SocketAsync_new (arena);

          /* Process with various timeouts */
          int timeout = (int)(get_uint16 (data, 1, size) % 10);
          SocketAsync_process_completions (async, timeout);
          SocketAsync_process_completions (async, 0);

          SocketAsync_free (&async);
        }
        break;

      case OP_MULTI_SUBMIT:
        {
          /* Submit multiple requests */
          async = SocketAsync_new (arena);
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          int count = (size > 3 ? data[3] % 16 : 4) + 1;

          for (int i = 0; i < count && num_requests < 32; i++)
            {
              unsigned req_id;
              if (i % 2 == 0)
                {
                  req_id = SocketAsync_send (async, socket, send_buf,
                                             64 + (i * 10), test_callback,
                                             NULL, ASYNC_FLAG_NONE);
                }
              else
                {
                  req_id = SocketAsync_recv (async, socket, recv_buf,
                                             64 + (i * 10), test_callback,
                                             NULL, ASYNC_FLAG_NONE);
                }
              if (req_id > 0)
                request_ids[num_requests++] = req_id;
            }

          /* Cancel some requests */
          for (int i = 0; i < num_requests; i += 2)
            {
              SocketAsync_cancel (async, request_ids[i]);
            }

          Socket_free (&socket);
          SocketAsync_free (&async);
        }
        break;

      case OP_ACCESSORS:
        {
          /* Test all accessor functions */
          async = SocketAsync_new (arena);

          int available = SocketAsync_is_available (async);
          const char *backend = SocketAsync_backend_name (async);

          /* Verify backend name is valid */
          assert (backend != NULL);
          assert (strlen (backend) > 0);

          /* Available should be 0 or 1 */
          assert (available == 0 || available == 1);

          SocketAsync_free (&async);
        }
        break;

      case OP_STRESS_HASH:
        {
          /* Stress test request hash table with many requests */
          async = SocketAsync_new (arena);
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Submit many requests to stress hash table */
          int count = (size > 3 ? data[3] % 64 : 32) + 8;

          for (int i = 0; i < count && num_requests < 32; i++)
            {
              unsigned req_id = SocketAsync_send (
                  async, socket, send_buf, 16 + (i % 100), test_callback,
                  (void *)(uintptr_t)i,
                  (i % 2) ? ASYNC_FLAG_URGENT : ASYNC_FLAG_NONE);
              if (req_id > 0 && num_requests < 32)
                request_ids[num_requests++] = req_id;
            }

          /* Cancel in random order based on fuzz data */
          for (size_t i = 4; i < size && i - 4 < (size_t)num_requests; i++)
            {
              int idx = data[i] % num_requests;
              if (request_ids[idx] != 0)
                {
                  SocketAsync_cancel (async, request_ids[idx]);
                  request_ids[idx] = 0;
                }
            }

          /* Cancel remaining */
          for (int i = 0; i < num_requests; i++)
            {
              if (request_ids[i] != 0)
                SocketAsync_cancel (async, request_ids[i]);
            }

          Socket_free (&socket);
          SocketAsync_free (&async);
        }
        break;

      default:
        break;
      }
  }
  EXCEPT (SocketAsync_Failed) { /* Expected for some operations */ }
  EXCEPT (Socket_Failed) { /* Expected for socket operations */ }
  ELSE { /* Other exceptions - also OK for fuzzing */ }
  END_TRY;

  /* Cleanup */
  if (socket)
    Socket_free (&socket);
  if (async)
    SocketAsync_free (&async);
  if (arena)
    Arena_dispose (&arena);

  return 0;
}

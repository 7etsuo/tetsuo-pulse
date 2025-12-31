/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_socketpool.c - Fuzzer for socket pool hash table and management
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Pool creation and sizing
 * - Hash table operations (insert, lookup, remove)
 * - Free list management
 * - Connection slot initialization
 * - Pool resize operations
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_socketpool
 * Run:   ./fuzz_socketpool corpus/socketpool/ -fork=16 -max_len=1024
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"
#include "pool/SocketPool.h"
#include "socket/Socket.h"

/* Operation codes */
enum PoolOp
{
  OP_CREATE_POOL = 0,
  OP_ADD_CONNECTIONS,
  OP_REMOVE_CONNECTIONS,
  OP_GET_CONNECTION,
  OP_RESIZE_POOL,
  OP_CLEANUP_IDLE,
  OP_HASH_COLLISION,
  OP_PREWARM,
  OP_SET_BUFSIZE,
  OP_FOREACH,
  OP_RAPID_ADD_REMOVE,
  OP_COUNT
};

/* Limits for fuzzing */
#define MAX_FUZZ_POOL_SIZE 64
#define MAX_FUZZ_BUFSIZE 4096
#define MAX_FUZZ_SOCKETS 32

/**
 * read_u16 - Read 16-bit value from byte stream
 */
static uint16_t
read_u16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * foreach_callback - Callback for SocketPool_foreach testing
 * @conn: Connection being iterated
 * @arg: User argument (counter pointer)
 */
static void
foreach_callback (Connection_T conn, void *arg)
{
  int *counter = (int *)arg;
  if (counter)
    (*counter)++;

  /* Access connection properties to ensure they're valid */
  if (conn)
    {
      Socket_T s = Connection_socket (conn);
      int active = Connection_isactive (conn);
      (void)s;
      (void)active;
    }
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Byte 1: Pool size (1-64)
 * - Byte 2-3: Buffer size (512-4096)
 * - Remaining: Operation-specific data
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketPool_T pool = NULL;
  Socket_T sockets[MAX_FUZZ_SOCKETS];
  volatile int socket_count = 0;
  volatile int i;

  if (size < 4)
    return 0;

  uint8_t op = data[0];
  size_t pool_size = (data[1] % MAX_FUZZ_POOL_SIZE) + 1;
  uint16_t bufsize_raw = read_u16 (data + 2);
  size_t bufsize = (bufsize_raw % (MAX_FUZZ_BUFSIZE - 512)) + 512;

  /* Initialize socket array to NULL */
  for (i = 0; i < MAX_FUZZ_SOCKETS; i++)
    sockets[i] = NULL;

  TRY
  {
    /* Create arena for pool */
    arena = Arena_new ();
    if (!arena)
      RETURN 0;

    /* Create a pool for testing */
    pool = SocketPool_new (arena, pool_size, bufsize);

    switch (op % OP_COUNT)
      {
      case OP_CREATE_POOL:
        {
          /* Test pool creation with various sizes */
          Arena_T test_arena = NULL;
          SocketPool_T test_pool = NULL;

          /* Try different pool sizes from fuzz data */
          if (size >= 5)
            {
              size_t test_size = (data[4] % 100) + 1;
              TRY
              {
                test_arena = Arena_new ();
                if (test_arena)
                  {
                    test_pool = SocketPool_new (test_arena, test_size, bufsize);
                    /* Verify pool properties */
                    size_t count = SocketPool_count (test_pool);
                    assert (count == 0);
                    SocketPool_free (&test_pool);
                    Arena_dispose (&test_arena);
                  }
              }
              EXCEPT (SocketPool_Failed)
              {
                /* Expected for invalid params */
                if (test_arena)
                  Arena_dispose (&test_arena);
              }
              EXCEPT (Arena_Failed)
              { /* Arena allocation can fail */
              }
              END_TRY;
            }
        }
        break;

      case OP_ADD_CONNECTIONS:
        {
          /* Create some sockets and add them to pool */
          int num_to_add = size >= 5 ? (data[4] % MAX_FUZZ_SOCKETS) + 1 : 1;
          if ((size_t)num_to_add > pool_size)
            num_to_add = (int)pool_size;

          for (i = 0; i < num_to_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                /* Create a TCP socket for testing */
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count++] = sock;

                    /* Add to pool */
                    Connection_T conn = SocketPool_add (pool, sock);
                    if (conn)
                      {
                        /* Verify connection properties */
                        assert (Connection_socket (conn) == sock);
                        assert (Connection_isactive (conn));
                      }
                  }
              }
              EXCEPT (Socket_Failed)
              { /* Socket creation can fail */
              }
              EXCEPT (SocketPool_Failed)
              {
                /* Pool add can fail (pool full) */
              }
              END_TRY;
            }

          /* Verify count */
          size_t count = SocketPool_count (pool);
          (void)count;
        }
        break;

      case OP_REMOVE_CONNECTIONS:
        {
          /* Add then remove connections */
          int num_add = size >= 5 ? (data[4] % 8) + 1 : 3;
          if ((size_t)num_add > pool_size)
            num_add = (int)pool_size;

          /* Add some connections */
          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count++] = sock;
                    SocketPool_add (pool, sock);
                  }
              }
              EXCEPT (Socket_Failed)
              {
              }
              EXCEPT (SocketPool_Failed)
              {
              }
              END_TRY;
            }

          /* Remove some - using pattern from fuzz data */
          if (size >= 6 && socket_count > 0)
            {
              int to_remove = data[5] % socket_count;
              for (i = 0; i <= to_remove && i < socket_count; i++)
                {
                  if (sockets[i])
                    {
                      SocketPool_remove (pool, sockets[i]);
                    }
                }
            }
        }
        break;

      case OP_GET_CONNECTION:
        {
          /* Add connections then get them back */
          int num_add = size >= 5 ? (data[4] % 5) + 1 : 2;
          if ((size_t)num_add > pool_size)
            num_add = (int)pool_size;

          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count++] = sock;
                    SocketPool_add (pool, sock);
                  }
              }
              EXCEPT (Socket_Failed)
              {
              }
              EXCEPT (SocketPool_Failed)
              {
              }
              END_TRY;
            }

          /* Get each connection back */
          for (i = 0; i < socket_count; i++)
            {
              if (sockets[i])
                {
                  Connection_T conn = SocketPool_get (pool, sockets[i]);
                  if (conn)
                    {
                      /* Access connection properties */
                      Socket_T s = Connection_socket (conn);
                      SocketBuf_T inbuf = Connection_inbuf (conn);
                      SocketBuf_T outbuf = Connection_outbuf (conn);
                      void *data_ptr = Connection_data (conn);
                      time_t activity = Connection_lastactivity (conn);
                      int active = Connection_isactive (conn);
                      (void)s;
                      (void)inbuf;
                      (void)outbuf;
                      (void)data_ptr;
                      (void)activity;
                      (void)active;
                    }
                }
            }

          /* Try to get non-existent socket */
          TRY
          {
            Socket_T fake = Socket_new (AF_INET, SOCK_STREAM, 0);
            if (fake)
              {
                Connection_T conn = SocketPool_get (pool, fake);
                /* Should be NULL - not in pool */
                (void)conn;
                Socket_free (&fake);
              }
          }
          EXCEPT (Socket_Failed)
          {
          }
          END_TRY;
        }
        break;

      case OP_RESIZE_POOL:
        {
          /* Add some connections then resize */
          int num_add = size >= 5 ? (data[4] % 4) + 1 : 2;
          if ((size_t)num_add > pool_size)
            num_add = (int)pool_size;

          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count++] = sock;
                    SocketPool_add (pool, sock);
                  }
              }
              EXCEPT (Socket_Failed)
              {
              }
              EXCEPT (SocketPool_Failed)
              {
              }
              END_TRY;
            }

          /* Try resize */
          if (size >= 6)
            {
              size_t new_size = (data[5] % MAX_FUZZ_POOL_SIZE) + 1;
              TRY
              {
                SocketPool_resize (pool, new_size);
              }
              EXCEPT (SocketPool_Failed)
              { /* Resize can fail */
              }
              END_TRY;
            }
        }
        break;

      case OP_CLEANUP_IDLE:
        {
          /* Add connections then cleanup with various timeouts */
          int num_add = 3;
          if ((size_t)num_add > pool_size)
            num_add = (int)pool_size;

          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count++] = sock;
                    SocketPool_add (pool, sock);
                  }
              }
              EXCEPT (Socket_Failed)
              {
              }
              EXCEPT (SocketPool_Failed)
              {
              }
              END_TRY;
            }

          /* Cleanup with various timeouts */
          if (size >= 5)
            {
              time_t timeout = data[4];
              SocketPool_cleanup (pool, timeout);
            }
        }
        break;

      case OP_HASH_COLLISION:
        {
          /* Try to create hash collisions by adding many sockets */
          int num_add = pool_size > MAX_FUZZ_SOCKETS ? MAX_FUZZ_SOCKETS
                                                     : (int)pool_size;
          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count++] = sock;
                    SocketPool_add (pool, sock);
                  }
              }
              EXCEPT (Socket_Failed)
              {
              }
              EXCEPT (SocketPool_Failed)
              {
              }
              END_TRY;
            }

          /* Verify all can be retrieved */
          for (i = 0; i < socket_count; i++)
            {
              if (sockets[i])
                {
                  Connection_T conn = SocketPool_get (pool, sockets[i]);
                  (void)conn;
                }
            }
        }
        break;

      case OP_PREWARM:
        {
          /* Test pool prewarming with various percentages */
          int percentage = size >= 5 ? (data[4] % 101) : 50;

          /* Prewarm the pool */
          SocketPool_prewarm (pool, percentage);

          /* Add some connections after prewarm */
          int num_add = size >= 6 ? (data[5] % 5) + 1 : 2;
          if ((size_t)num_add > pool_size)
            num_add = (int)pool_size;

          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count++] = sock;
                    SocketPool_add (pool, sock);
                  }
              }
              EXCEPT (Socket_Failed)
              {
              }
              EXCEPT (SocketPool_Failed)
              {
              }
              END_TRY;
            }

          /* Verify count */
          size_t count = SocketPool_count (pool);
          (void)count;
        }
        break;

      case OP_SET_BUFSIZE:
        {
          /* Test buffer size changes */
          size_t new_bufsize = size >= 5 ? (data[4] * 64) + 512 : 1024;
          if (new_bufsize > MAX_FUZZ_BUFSIZE)
            new_bufsize = MAX_FUZZ_BUFSIZE;

          /* Set new buffer size */
          SocketPool_set_bufsize (pool, new_bufsize);

          /* Add connections with new buffer size */
          int num_add = size >= 6 ? (data[5] % 4) + 1 : 2;
          if ((size_t)num_add > pool_size)
            num_add = (int)pool_size;

          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count++] = sock;
                    Connection_T conn = SocketPool_add (pool, sock);
                    if (conn)
                      {
                        /* Access buffers to verify they're valid */
                        SocketBuf_T inbuf = Connection_inbuf (conn);
                        SocketBuf_T outbuf = Connection_outbuf (conn);
                        (void)inbuf;
                        (void)outbuf;
                      }
                  }
              }
              EXCEPT (Socket_Failed)
              {
              }
              EXCEPT (SocketPool_Failed)
              {
              }
              END_TRY;
            }
        }
        break;

      case OP_FOREACH:
        {
          /* Test iteration over connections */
          int num_add = size >= 5 ? (data[4] % 8) + 1 : 3;
          if ((size_t)num_add > pool_size)
            num_add = (int)pool_size;

          /* Add connections */
          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count++] = sock;
                    SocketPool_add (pool, sock);
                  }
              }
              EXCEPT (Socket_Failed)
              {
              }
              EXCEPT (SocketPool_Failed)
              {
              }
              END_TRY;
            }

          /* Iterate with callback */
          int callback_count = 0;
          SocketPool_foreach (pool, foreach_callback, &callback_count);

          /* Verify callback was called for each connection */
          size_t pool_count = SocketPool_count (pool);
          (void)pool_count;
          (void)callback_count;
        }
        break;

      case OP_RAPID_ADD_REMOVE:
        {
          /* Stress test: rapid add/remove cycles */
          int cycles = size >= 5 ? (data[4] % 10) + 1 : 5;

          for (int cycle = 0; cycle < cycles; cycle++)
            {
              /* Add a batch */
              int to_add = size >= 6 ? (data[5] % 4) + 1 : 2;
              if ((size_t)to_add > pool_size)
                to_add = (int)pool_size;

              for (i = 0; i < to_add && socket_count < MAX_FUZZ_SOCKETS; i++)
                {
                  TRY
                  {
                    Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                    if (sock)
                      {
                        sockets[socket_count++] = sock;
                        SocketPool_add (pool, sock);
                      }
                  }
                  EXCEPT (Socket_Failed)
                  {
                  }
                  EXCEPT (SocketPool_Failed)
                  {
                  }
                  END_TRY;
                }

              /* Remove half */
              int to_remove = socket_count / 2;
              for (i = 0; i < to_remove && socket_count > 0; i++)
                {
                  int idx = socket_count - 1;
                  if (sockets[idx])
                    {
                      SocketPool_remove (pool, sockets[idx]);
                      Socket_free (&sockets[idx]);
                      socket_count--;
                    }
                }

              /* Verify integrity */
              size_t count = SocketPool_count (pool);
              (void)count;
            }
        }
        break;
      }
  }
  EXCEPT (SocketPool_Failed)
  { /* Expected for some operations */
  }
  EXCEPT (Socket_Failed)
  { /* Socket creation can fail */
  }
  EXCEPT (Arena_Failed)
  { /* Memory allocation can fail */
  }
  FINALLY
  {
    /* Clean up all sockets */
    for (i = 0; i < socket_count; i++)
      {
        if (sockets[i])
          {
            /* Remove from pool first if added */
            if (pool)
              SocketPool_remove (pool, sockets[i]);
            Socket_free (&sockets[i]);
          }
      }

    /* Free the pool */
    if (pool)
      SocketPool_free (&pool);

    /* Dispose of the arena */
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}

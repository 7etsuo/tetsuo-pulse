/**
 * fuzz_socketpoll.c - Fuzzer for event poll operations
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Poll creation with various maxevents
 * - Socket add/mod/del operations
 * - Duplicate detection
 * - Hash table stress testing
 * - Timeout handling
 * - Rapid add/remove sequences
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_socketpoll
 * Run:   ./fuzz_socketpoll corpus/socketpoll/ -fork=16 -max_len=1024
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

/* Operation codes */
enum PollOp
{
  OP_CREATE_POLL = 0,
  OP_ADD_SOCKETS,
  OP_MOD_EVENTS,
  OP_DEL_SOCKETS,
  OP_WAIT_TIMEOUT,
  OP_DUPLICATE_ADD,
  OP_RAPID_ADD_DEL,
  OP_TIMEOUT_CONFIG,
  OP_COUNT
};

/* Limits for fuzzing */
#define MAX_FUZZ_MAXEVENTS 64
#define MIN_FUZZ_MAXEVENTS 4
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
 * read_i16 - Read signed 16-bit value from byte stream
 */
static int16_t
read_i16 (const uint8_t *p)
{
  return (int16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Byte 1: maxevents (clamped)
 * - Bytes 2-3: timeout value
 * - Remaining: Operation sequence data
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketPoll_T poll = NULL;
  Socket_T sockets[MAX_FUZZ_SOCKETS];
  volatile int socket_count = 0;
  volatile int i;

  if (size < 4)
    return 0;

  uint8_t op = data[0];
  int maxevents = (data[1] % (MAX_FUZZ_MAXEVENTS - MIN_FUZZ_MAXEVENTS))
                  + MIN_FUZZ_MAXEVENTS;
  int16_t timeout_raw = read_i16 (data + 2);

  /* Initialize socket array to NULL */
  for (i = 0; i < MAX_FUZZ_SOCKETS; i++)
    sockets[i] = NULL;

  TRY
  {
    /* Create a poll for testing */
    poll = SocketPoll_new (maxevents);

    switch (op % OP_COUNT)
      {
      case OP_CREATE_POLL:
        {
          /* Test poll creation with various maxevents */
          SocketPoll_T test_poll = NULL;

          /* Try different maxevents values from fuzz data */
          if (size >= 5)
            {
              int test_maxevents = data[4] + 1; /* 1-256 */
              TRY
              {
                test_poll = SocketPoll_new (test_maxevents);

                /* Verify default timeout */
                int default_timeout = SocketPoll_getdefaulttimeout (test_poll);
                (void)default_timeout;

                SocketPoll_free (&test_poll);
              }
              EXCEPT (SocketPoll_Failed)
              {
                /* Expected for invalid maxevents */
              }
              END_TRY;
            }
        }
        break;

      case OP_ADD_SOCKETS:
        {
          /* Test adding sockets to poll */
          int num_to_add = size >= 5 ? (data[4] % MAX_FUZZ_SOCKETS) + 1 : 4;

          for (i = 0; i < num_to_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count] = sock;

                    /* Determine events from fuzz data */
                    unsigned events = POLL_READ;
                    if (size >= 6 + (size_t)i)
                      {
                        if (data[5 + i] & 0x01)
                          events |= POLL_WRITE;
                      }

                    /* Add to poll */
                    SocketPoll_add (poll, sock, events, (void *)(uintptr_t)i);
                    socket_count++;
                  }
              }
              EXCEPT (Socket_Failed) { /* Socket creation can fail */ }
              EXCEPT (SocketPoll_Failed) { /* Poll add can fail */ }
              END_TRY;
            }
        }
        break;

      case OP_MOD_EVENTS:
        {
          /* Add sockets then modify their events */
          int num_add = size >= 5 ? (data[4] % 8) + 1 : 4;

          /* Add some sockets */
          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count] = sock;
                    SocketPoll_add (poll, sock, POLL_READ, NULL);
                    socket_count++;
                  }
              }
              EXCEPT (Socket_Failed) {}
              EXCEPT (SocketPoll_Failed) {}
              END_TRY;
            }

          /* Modify events on some sockets */
          if (size >= 6 && socket_count > 0)
            {
              int to_mod = data[5] % socket_count;
              for (i = 0; i <= to_mod && i < socket_count; i++)
                {
                  if (sockets[i])
                    {
                      TRY
                      {
                        unsigned new_events = POLL_READ | POLL_WRITE;
                        if (size >= 7 + (size_t)i && (data[6 + i] & 0x01))
                          new_events = POLL_WRITE;
                        SocketPoll_mod (poll, sockets[i], new_events,
                                        (void *)(uintptr_t)(i + 100));
                      }
                      EXCEPT (SocketPoll_Failed) { /* Mod can fail */ }
                      END_TRY;
                    }
                }
            }
        }
        break;

      case OP_DEL_SOCKETS:
        {
          /* Add sockets then remove them */
          int num_add = size >= 5 ? (data[4] % 10) + 1 : 5;

          /* Add sockets */
          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count] = sock;
                    SocketPoll_add (poll, sock, POLL_READ, NULL);
                    socket_count++;
                  }
              }
              EXCEPT (Socket_Failed) {}
              EXCEPT (SocketPoll_Failed) {}
              END_TRY;
            }

          /* Remove some using pattern from fuzz data */
          if (size >= 6 && socket_count > 0)
            {
              int to_del = data[5] % socket_count;
              for (i = 0; i <= to_del && i < socket_count; i++)
                {
                  if (sockets[i])
                    {
                      TRY { SocketPoll_del (poll, sockets[i]); }
                      EXCEPT (SocketPoll_Failed) { /* Del can fail */ }
                      END_TRY;
                    }
                }
            }

          /* Try to delete same socket again (should handle gracefully) */
          if (socket_count > 0 && sockets[0])
            {
              TRY { SocketPoll_del (poll, sockets[0]); }
              EXCEPT (SocketPoll_Failed)
              {
                /* Expected - socket already removed or not in poll */
              }
              END_TRY;
            }
        }
        break;

      case OP_WAIT_TIMEOUT:
        {
          /* Add some sockets then wait with various timeouts */
          int num_add = 3;

          for (i = 0; i < num_add && socket_count < MAX_FUZZ_SOCKETS; i++)
            {
              TRY
              {
                Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                if (sock)
                  {
                    sockets[socket_count] = sock;
                    SocketPoll_add (poll, sock, POLL_READ | POLL_WRITE, NULL);
                    socket_count++;
                  }
              }
              EXCEPT (Socket_Failed) {}
              EXCEPT (SocketPoll_Failed) {}
              END_TRY;
            }

          /* Wait with short timeout (0 for immediate return) */
          SocketEvent_T *events = NULL;
          TRY
          {
            int timeout = 0; /* Don't block in fuzzer */
            int n = SocketPoll_wait (poll, &events, timeout);
            (void)n;
            (void)events;
          }
          EXCEPT (SocketPoll_Failed) { /* Wait can fail */ }
          END_TRY;
        }
        break;

      case OP_DUPLICATE_ADD:
        {
          /* Test duplicate add detection */
          TRY
          {
            Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
            if (sock)
              {
                sockets[socket_count++] = sock;

                /* Add first time - should succeed */
                SocketPoll_add (poll, sock, POLL_READ, NULL);

                /* Add second time - should fail */
                TRY { SocketPoll_add (poll, sock, POLL_WRITE, NULL); }
                EXCEPT (SocketPoll_Failed)
                {
                  /* Expected - duplicate add detected */
                }
                END_TRY;
              }
          }
          EXCEPT (Socket_Failed) {}
          EXCEPT (SocketPoll_Failed) {}
          END_TRY;
        }
        break;

      case OP_RAPID_ADD_DEL:
        {
          /* Stress test: rapid add/del cycles */
          int cycles = size >= 5 ? (data[4] % 10) + 1 : 5;

          for (int cycle = 0; cycle < cycles; cycle++)
            {
              /* Add a batch */
              int to_add = size >= 6 ? (data[5] % 4) + 1 : 2;

              for (i = 0; i < to_add && socket_count < MAX_FUZZ_SOCKETS; i++)
                {
                  TRY
                  {
                    Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
                    if (sock)
                      {
                        sockets[socket_count] = sock;
                        SocketPoll_add (poll, sock, POLL_READ, NULL);
                        socket_count++;
                      }
                  }
                  EXCEPT (Socket_Failed) {}
                  EXCEPT (SocketPoll_Failed) {}
                  END_TRY;
                }

              /* Remove half */
              int to_del = socket_count / 2;
              for (i = 0; i < to_del && socket_count > 0; i++)
                {
                  int idx = socket_count - 1;
                  if (sockets[idx])
                    {
                      TRY { SocketPoll_del (poll, sockets[idx]); }
                      EXCEPT (SocketPoll_Failed) {}
                      END_TRY;
                      Socket_free (&sockets[idx]);
                      socket_count--;
                    }
                }
            }
        }
        break;

      case OP_TIMEOUT_CONFIG:
        {
          /* Test timeout configuration */
          int original = SocketPoll_getdefaulttimeout (poll);
          (void)original;

          /* Set various timeouts from fuzz data */
          int new_timeout = timeout_raw; /* Can be negative */
          SocketPoll_setdefaulttimeout (poll, new_timeout);

          int current = SocketPoll_getdefaulttimeout (poll);
          (void)current;

          /* Test edge cases */
          SocketPoll_setdefaulttimeout (poll, -1); /* Infinite */
          SocketPoll_setdefaulttimeout (poll, 0);  /* Immediate */
          SocketPoll_setdefaulttimeout (poll,
                                        -99); /* Invalid - should clamp */

          /* Add a socket and wait with default timeout */
          TRY
          {
            Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
            if (sock)
              {
                sockets[socket_count++] = sock;
                SocketPoll_add (poll, sock, POLL_READ, NULL);

                /* Wait with SOCKET_POLL_TIMEOUT_USE_DEFAULT to use poll's
                 * default */
                SocketEvent_T *events = NULL;
                SocketPoll_setdefaulttimeout (poll,
                                              0); /* Ensure immediate return */
                int n = SocketPoll_wait (poll, &events,
                                         SOCKET_POLL_TIMEOUT_USE_DEFAULT);
                (void)n;
              }
          }
          EXCEPT (Socket_Failed) {}
          EXCEPT (SocketPoll_Failed) {}
          END_TRY;
        }
        break;
      }
  }
  EXCEPT (SocketPoll_Failed) { /* Expected for some operations */ }
  EXCEPT (Socket_Failed) { /* Socket creation can fail */ }
  EXCEPT (Arena_Failed) { /* Memory allocation can fail */ }
  FINALLY
  {
    /* Clean up sockets - remove from poll first if they were added */
    for (i = 0; i < socket_count; i++)
      {
        if (sockets[i])
          {
            if (poll)
              {
                TRY { SocketPoll_del (poll, sockets[i]); }
                EXCEPT (SocketPoll_Failed) { /* May already be removed */ }
                END_TRY;
              }
            Socket_free (&sockets[i]);
          }
      }

    /* Free the poll */
    if (poll)
      SocketPoll_free (&poll);
  }
  END_TRY;

  return 0;
}
